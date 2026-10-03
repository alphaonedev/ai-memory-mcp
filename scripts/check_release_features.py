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

DESIGN: AN ALLOWLIST OF TEXT *AND* OF POSITION. The units that decide what
ships are compared to their EXACT expected text, after normalising only
spaces/tabs and ``\\`` line continuation; anything else is refused:

  * the release.yml build step, the strict-assert step, the SBOM step and the
    release-shape build step (statement lists, below);
  * the Dockerfile builder ``RUN`` (one instruction string).

Pinning the text alone is not enough: a unit can be copied into a position
that never runs (a YAML block scalar, a dead Docker stage, a decoy job) while
the unit that does run is changed, or the values GitHub substitutes into the
pinned text (``${{ matrix.* }}``) can carry shell. So the guard also pins WHERE
each unit is and WHAT is substituted into it:

  * Workflows are read with a strict, fail-closed YAML SUBSET parser (stdlib
    only, no PyYAML). It accepts ``key:``, ``key: value`` (a one-line plain,
    quoted or flow-sequence value), ``key: |`` / ``|-`` / ``>`` / ``>-`` and
    ``- `` sequence items whose first key sits exactly two columns after the
    dash, with ONE indentation per mapping. It refuses every line it cannot
    explain: tabs, a line more indented than its mapping or sequence (a
    multi-line scalar or a stray key), quoted or complex keys, duplicate keys,
    anchors, aliases, tags, flow mappings, multi-line quoted scalars, block
    indentation indicators. A block scalar is allowed ONLY as a step ``run:``
    or a step ``with:`` value, so ``name: |`` cannot hide steps.
  * The units are located structurally: top-level ``jobs:`` -> ``release:`` ->
    its ``steps:`` list (build, then strict assert, exactly one of each),
    ``jobs:`` -> ``sbom:`` -> ``steps:`` (exactly one SBOM step; a second
    ``cargo ... cyclonedx`` anywhere in release.yml is refused), and the
    release-shape ``jobs:`` -> ``release-shape:`` -> ``steps:``.
  * The release job SKELETON is pinned: its key set is exactly ``JOB_KEYS``,
    ``runs-on`` is exactly ``${{ matrix.os }}``, and ``strategy`` is exactly
    ``fail-fast: false`` plus ``matrix: include:`` entries whose keys are
    ``target``/``os``/``artifact`` (+ ``nfpm_arch``) and whose values are
    unquoted literals matching a strict pattern (no expression, quote, space or
    shell metacharacter: they are substituted into the pinned build and assert
    text before bash runs). The target set itself is pinned (``RELEASE_TARGETS``):
    a legitimate matrix change updates that constant in the same commit. This
    pin is deliberate: an exact skeleton is cheaper to keep correct than an
    open-ended list of job keys that can skip, redirect or neutralise the
    assert (``if:``, ``env:``, ``defaults:``, ``container:``,
    ``continue-on-error:``...). A pinned step ``name:`` must not carry ``${{``.
  * In the release job no step other than the canonical build may mention
    ``cargo``, ``rustc``, ``cross`` or ``cargo-zigbuild`` (any case, any option
    order, any ``+toolchain``), and in the whole of release.yml at most one
    line runs one of them against ``matrix.target``. This is a REFUSAL, not
    tracking: it does not prove the uploaded file is the asserted one (#4752).
  * Dockerfile: line 1 must be exactly ``# syntax=docker/dockerfile:1`` and no
    other parser directive (``escape``, ``check``, a second ``syntax``) may
    appear anywhere; heredocs (``<<``), ``SHELL``, ``ONBUILD`` and unknown
    instructions are refused. Stages are parsed: the final stage must COPY the
    binary exactly once, from a NAMED earlier stage, and take nothing else
    ``--from`` another stage or image; that stage (the builder) must not start
    FROM another stage nor COPY ``--from``, must COPY Cargo.lock, and must end
    with exactly the declaration COPY followed by the canonical RUN. ``cargo``
    anywhere else in the Dockerfile is refused. The docker job must not pass a
    ``target:`` or ``file:`` to docker/build-push-action (that would ship
    another stage or file).

Whole-line comments are dropped; a trailing ``#`` is NOT trusted (the statement
then differs from the allowed one and is refused). ``BASH_ENV`` is refused
anywhere in release.yml and the Dockerfile. Control characters (CR, form feed,
NUL...), NBSP and every other Unicode space or zero-width character in the
workflows or Dockerfile are refused, never folded: Python, YAML and bash
disagree on what a line and a blank are.

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
from typing import Callable, Dict, Iterator, List, Optional, Tuple, Union

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
DOCKER_SYNTAX = "# syntax=docker/dockerfile:1"
DOCKER_DECL_COPY = "COPY scripts/release-features.sh scripts/release-features.sh"
DOCKER_LOCK_COPY = "COPY Cargo.toml Cargo.lock ./"
DOCKER_INSTRUCTIONS = frozenset((
    "FROM", "RUN", "CMD", "LABEL", "EXPOSE", "ENV", "ADD", "COPY", "ENTRYPOINT",
    "VOLUME", "USER", "WORKDIR", "ARG", "STOPSIGNAL", "HEALTHCHECK",
))

KEYS_SHELL = ("name", "shell", "run")
KEYS_PLAIN = ("name", "run")
TOP_KEYS = ("name", "on", "permissions", "concurrency", "jobs")
JOB_KEYS = ("name", "needs", "runs-on", "permissions", "strategy", "steps")
SBOM_JOB_KEYS = ("name", "needs", "runs-on", "permissions", "steps")
RELEASE_RUNS_ON = "${{ matrix.os }}"
# The release matrix. Every value is substituted textually into the pinned
# build / assert units before bash runs, so each one is a strict literal.
RELEASE_TARGETS = (
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
)
MATRIX_REQUIRED = ("target", "os", "artifact")
MATRIX_VALUE_RE = {
    "target": re.compile(r"[a-z0-9_]+(?:-[a-z0-9_]+){2,3}"),
    "os": re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*"),
    "artifact": re.compile(r"ai-memory"),
    "nfpm_arch": re.compile(r"[a-z0-9_]+"),
}

# A build tool word: any case (macOS runners resolve `CARGO` on a case-insensitive
# file system), not part of a longer word, option or file name (`Cargo.toml`).
BUILD_TOOL_RE = re.compile(r"(?<![\w.-])(?:cargo-zigbuild|cargo|rustc|cross)(?![\w.-])", re.I)
SBOM_TOOL_RE = re.compile(r"(?<![\w-])cargo(?![\w-]).*?\scyclonedx(?![\w-])", re.I)
INLINE_USE_RE = re.compile(r"\$\(\s*bash [^)]*release-features\.sh|`\s*bash [^`]*release-features\.sh")
# C0/C1 controls (tab excepted: the YAML parser refuses it itself), every Unicode
# space other than U+0020 (NBSP, ogham, en/em..., narrow NBSP, math space,
# ideographic), zero-width characters and the BOM, line/paragraph separators.
CONTROL_RE = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f-\x9f\u00a0\u1680\u180e\u2000-\u200f\u2028-\u202f\u205f-\u2064\u3000\ufeff]"
)
KEY_RE = re.compile(r"(?P<key>[A-Za-z_][A-Za-z0-9_-]*):(?: +(?P<val>.*))?")
ITEM_RE = re.compile(r"-(?P<sp> *)(?P<rest>.*)")
BLOCK_INDICATORS = ("|", "|-", ">", ">-")
_TAIL = r"(?:[ ]+#.*)?"
_FLOW_ITEM = r"(?:\"[^\"\\]*\"|'[^']*'|[^\s\[\]{},'\"#&*!|>%@`][^\[\]{},#]*?)"
SCALAR_FORMS = (
    ("double", re.compile(r'(?P<v>"(?:[^"\\]|\\.)*")' + _TAIL)),
    ("single", re.compile(r"(?P<v>'(?:[^']|'')*')" + _TAIL)),
    ("flow", re.compile(r"(?P<v>\[ *(?:" + _FLOW_ITEM + r"(?: *, *" + _FLOW_ITEM + r")*)? *\])" + _TAIL)),
    ("plain", re.compile(r"(?P<v>(?:[^\s&*!{}\[\]|>%@`#,'\"?:-]|[-?:](?=\S))(?:(?!: |:$| #).)*?)" + _TAIL)),
)
FROM_RE = re.compile(r"FROM(?: --platform=\S+)? (?P<image>\S+)(?: AS (?P<name>[A-Za-z][A-Za-z0-9_.-]*))?", re.I)
BINARY_COPY_RE = re.compile(r"COPY --from=(?P<stage>\S+) /build/target/release/ai-memory /usr/local/bin/ai-memory")
FROM_FLAG_RE = re.compile(r"--from=(?P<src>\S+)", re.I)
DIRECTIVE_RE = re.compile(r"^[ \t]*#[ \t]*(?:syntax|escape|check)[ \t]*=", re.I)


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
    s = line.strip(" \t")
    return not s or s.startswith("#")


def logical_lines(lines: List[str]) -> List[str]:
    """Normalise to logical lines: whole-line comments and blanks dropped, ``\\``
    continuations joined, runs of spaces/tabs collapsed (ONLY spaces and tabs:
    any other Unicode space is refused by CONTROL_RE, never folded). NOTHING
    else is interpreted: a trailing ``#`` stays in the line, and a comment line
    inside a continuation is kept (bash ends the command there), so extra text
    can only add refusals."""
    out: List[str] = []
    buf = ""
    for raw in lines:
        line = raw.strip(" \t")
        if not buf and (not line or line.startswith("#")):
            continue
        if line.endswith("\\"):
            buf += line[:-1].rstrip(" \t") + " "
            continue
        out.append(re.sub(r"[ \t]+", " ", buf + line).strip(" "))
        buf = ""
    if buf.strip(" \t"):
        out.append(re.sub(r"[ \t]+", " ", buf).strip(" "))
    return out


def code_lines(text: str) -> str:
    """PRESENCE view of a file: whole-line comments dropped, trailing comments
    stripped."""
    return "\n".join(strip_comment(ln) for ln in text.split("\n") if not is_blank_or_comment(ln))


def first_diff(got: Tuple[str, ...], want: Tuple[str, ...]) -> str:
    """Name the first statement where ``got`` and ``want`` differ."""
    n = max(len(got), len(want))
    first = next((i for i in range(n) if i >= len(got) or i >= len(want) or got[i] != want[i]), 0)
    have = got[first] if first < len(got) else "<end of unit>"
    exp = want[first] if first < len(want) else "<end of unit>"
    return f"statement {first + 1} is `{have[:90]}`, the only allowed one is `{exp[:90]}`"


# ------------------------------------------------------------------ report --
class Report:
    def __init__(self) -> None:
        self.errors: List[str] = []

    def bad(self, msg: str) -> None:
        self.errors.append(msg)

    def first(self) -> str:
        return self.errors[0] if self.errors else ""


class InputError(Exception):
    """An input file could not be read or decoded: exit 2, never a traceback."""


def load(path: Path, label: str, rep: Report, strict: bool) -> Optional[str]:
    """Read one input. Missing = a guard failure (None). Anything else that stops
    a read (non-UTF-8, a directory, a symlink loop, no permission) = InputError,
    exit 2. ``strict`` refuses control characters and non-ASCII spaces."""
    try:
        text = path.read_bytes().decode("utf-8")  # bytes: text mode would fold CR away
    except FileNotFoundError:
        rep.bad(f"{label} is missing")
        return None
    except (OSError, ValueError) as exc:
        raise InputError(f"cannot read {label}: {exc}") from exc
    if strict:
        m = CONTROL_RE.search(text)
        if m:
            line = text.count("\n", 0, m.start()) + 1
            rep.bad(f"{label}: line {line}: control character or non-ASCII space U+{ord(m.group(0)):04X} "
                    "(Python, YAML and bash disagree on line ends and blanks; refused, never folded)")
            return None
    return text


# --------------------------------------------------------- YAML subset ----
class YamlError(Exception):
    """A line outside the subset grammar."""


class Node:
    """One node of the subset grammar. ``kind`` is map | seq | scalar | block |
    null; ``value`` is a dict (map), a list of nodes (seq), the text (scalar)
    or the content lines (block); ``style`` is the scalar style or the block
    indicator; ``line`` is the 0-based source line."""

    def __init__(self, kind: str, line: int, value: object, style: str = "") -> None:
        self.kind = kind
        self.line = line
        self.value = value
        self.style = style

    def get(self, key: str) -> Optional["Node"]:
        if self.kind != "map" or not isinstance(self.value, dict):
            return None
        return self.value.get(key)

    def keys(self) -> List[str]:
        return list(self.value) if self.kind == "map" and isinstance(self.value, dict) else []

    def text(self) -> str:
        return self.value if self.kind == "scalar" and isinstance(self.value, str) else ""


class YamlSubset:
    """Strict line parser; ``bad`` raises, so the first unexplained line stops
    the parse. (Each refusal is followed by a fallback that only a mutant with
    ``bad`` neutralised reaches: it lets ``--mutation-sweep`` prove the case.)"""

    def __init__(self, text: str, label: str) -> None:
        self.lines = text.split("\n")
        self.label = label
        self.i = 0

    def bad(self, n: int, msg: str) -> None:
        raise YamlError(f"{self.label}: line {n + 1}: {msg}")

    def peek(self) -> Optional[int]:
        j = self.i
        while j < len(self.lines) and is_blank_or_comment(self.lines[j]):
            j += 1
        return j if j < len(self.lines) else None

    def parse(self) -> Node:
        for n, ln in enumerate(self.lines):
            if "\t" in ln:
                self.bad(n, "tab character (refused everywhere: YAML forbids it in indentation and bash reads it as a blank)")
        return self.parse_map(0)

    def parse_map(self, ind: int) -> Node:
        node = Node("map", self.i, {})
        mapping: Dict[str, Node] = {}
        node.value = mapping
        while True:
            j = self.peek()
            if j is None:
                break
            line = self.lines[j]
            li = indent_of(line)
            if li < ind:
                break
            if li > ind:
                self.bad(j, f"line is more indented than its mapping (indent {li}, mapping keys at {ind}: a multi-line "
                            f"scalar or a stray key): {line.strip(' ')[:60]}")
                self.i = j + 1
                continue
            m = KEY_RE.fullmatch(line[li:])
            if m is None:
                self.bad(j, f"line outside the subset grammar (quoted or complex key, flow mapping, document marker...): "
                            f"{line.strip(' ')[:60]}")
                self.i = j + 1
                continue
            key = m.group("key")
            self.i = j + 1
            child = self.parse_value(j, ind, m.group("val") or "")
            if key in mapping:
                self.bad(j, f"duplicate key `{key}:`")
                continue
            mapping[key] = child
        return node

    def parse_value(self, j: int, ind: int, val: str) -> Node:
        if val.startswith("#"):
            val = ""
        if val == "":
            k = self.peek()
            if k is not None and indent_of(self.lines[k]) > ind:
                ci = indent_of(self.lines[k])
                if self.lines[k][ci:].startswith("-"):
                    return self.parse_seq(ci)
                return self.parse_map(ci)
            return Node("null", j, None)
        if val in BLOCK_INDICATORS:
            return self.parse_block(j, ind, val)
        return self.scalar(j, val)

    def scalar(self, j: int, val: str) -> Node:
        for style, rx in SCALAR_FORMS:
            m = rx.fullmatch(val)
            if m is not None:
                return Node("scalar", j, m.group("v") if style == "plain" else m.group("v")[1:-1], style)
        self.bad(j, f"value outside the subset grammar (multi-line or unterminated quote, anchor, alias, tag, flow "
                    f"mapping, block indentation indicator, `: ` in a plain value...): {val[:60]}")
        return Node("scalar", j, val, "plain")

    def parse_block(self, j: int, ind: int, indicator: str) -> Node:
        content: List[str] = []
        cind = -1
        k = j + 1
        while k < len(self.lines):
            raw = self.lines[k]
            if not raw.strip(" "):
                content.append("")
                k += 1
                continue
            ri = indent_of(raw)
            if ri <= ind:
                break
            if cind < 0:
                cind = ri
            if ri < cind:
                self.bad(k, f"block scalar line less indented ({ri}) than its first line ({cind})")
                content.append(raw.strip(" "))
                k += 1
                continue
            content.append(raw[cind:])
            k += 1
        self.i = k
        while content and content[-1] == "":
            content.pop()
        return Node("block", j, content, indicator)

    def parse_seq(self, s: int) -> Node:
        items: List[Node] = []
        node = Node("seq", self.i, items)
        while True:
            j = self.peek()
            if j is None:
                break
            line = self.lines[j]
            li = indent_of(line)
            if li < s:
                break
            if li > s:
                self.bad(j, f"line is more indented than its sequence (indent {li}, items at {s}): {line.strip(' ')[:60]}")
                self.i = j + 1
                continue
            m = ITEM_RE.fullmatch(line[li:])
            if m is None or m.group("sp") != " " or not m.group("rest"):
                self.bad(j, f"sequence line outside the subset grammar (`- ` takes exactly one space and a value on "
                            f"the same line): {line.strip(' ')[:60]}")
                if m is None:
                    self.i = j + 1
                    continue
            rest = m.group("rest").lstrip(" ")
            if KEY_RE.fullmatch(rest):
                self.lines[j] = " " * (s + 2) + rest
                self.i = j
                items.append(self.parse_map(s + 2))
            else:
                self.i = j + 1
                items.append(self.scalar(j, rest) if rest else Node("null", j, None))
        return node


def parse_yaml(text: str, label: str, rep: Report) -> Optional[Node]:
    try:
        return YamlSubset(text, label).parse()
    except YamlError as exc:
        rep.bad(str(exc))
        return None


def walk(node: Node, path: Tuple[str, ...] = ()) -> Iterator[Tuple[Tuple[str, ...], Node]]:
    yield path, node
    if node.kind == "map" and isinstance(node.value, dict):
        for k, v in node.value.items():
            yield from walk(v, path + (k,))
    elif node.kind == "seq" and isinstance(node.value, list):
        for n, v in enumerate(node.value):
            yield from walk(v, path + (str(n),))


def check_blocks(doc: Node, label: str, rep: Report) -> None:
    """A block scalar is allowed only as a step ``run:`` or a step ``with:`` value."""
    for path, node in walk(doc):
        if node.kind != "block":
            continue
        in_step = len(path) >= 5 and path[0] == "jobs" and path[2] == "steps"
        if in_step and ((len(path) == 5 and path[4] == "run") or (len(path) == 6 and path[4] == "with")):
            continue
        rep.bad(f"{label}: line {node.line + 1}: a block scalar (`|`/`>`) at `{'.'.join(path)}`; only a step `run:` "
                "or a step `with:` value may be one")


def want_kind(node: Optional[Node], kind: str, what: str, rep: Report) -> bool:
    if node is not None and node.kind == kind:
        return True
    rep.bad(f"{what} must be a {'mapping' if kind == 'map' else 'sequence' if kind == 'seq' else kind}"
            f" (got {'nothing' if node is None else node.kind})")
    return False


def node_texts(node: Node) -> Iterator[str]:
    """Every executable-looking text under ``node`` (scalars, and the logical
    lines of block scalars), skipping ``name:`` values."""
    for path, sub in walk(node):
        if path and path[-1] == "name":
            continue
        if sub.kind == "scalar":
            yield sub.text()
        elif sub.kind == "block" and isinstance(sub.value, list):
            yield from logical_lines(sub.value)


# ------------------------------------------------------------ step units --
def step_label(i: int, step: Node) -> str:
    name = step.get("name") or step.get("uses")
    return f"step {i + 1} `{name.text()[:60] if name is not None else '?'}`"


def run_lines(step: Node) -> Tuple[str, ...]:
    run = step.get("run")
    if run is None:
        return ()
    if run.kind == "block" and isinstance(run.value, list):
        return tuple(logical_lines(run.value))
    return tuple(logical_lines([run.text()]))


def step_problem(step: Node, want_keys: Tuple[str, ...], expected: Tuple[str, ...]) -> str:
    """Why ``step`` is not the allowed unit ("" when it is exactly that unit)."""
    why = Report()
    if set(step.keys()) != set(want_keys):
        why.bad(f"step keys {sorted(step.keys())} differ from the only allowed set {sorted(want_keys)}")
    name = step.get("name")
    if name is not None and "${{" in name.text():
        why.bad("the step `name:` carries a `${{ }}` expression (refused in a pinned unit)")
    run = step.get("run")
    if run is None or run.kind != "block" or run.style != "|":
        why.bad("`run:` must be a literal block (`run: |`); a folded, quoted or inline run is refused")
    shell = step.get("shell")
    if "shell" in want_keys and (shell is None or shell.style != "plain" or shell.text() != "bash"):
        why.bad(f"`shell: {shell.text() if shell is not None else ''}` (only an unquoted `shell: bash` is allowed)")
    got = run_lines(step)
    if got != expected:
        why.bad(first_diff(got, expected))
    return why.first()


def job_steps(job: Node, where: str, rep: Report) -> List[Tuple[int, Node]]:
    steps = job.get("steps")
    if steps is None or steps.kind != "seq" or not isinstance(steps.value, list):
        return []
    return [(i, st) for i, st in enumerate(steps.value) if want_kind(st, "map", f"{where} step {i + 1}", rep)]


def canonical(steps: List[Tuple[int, Node]], want_keys: Tuple[str, ...], expected: Tuple[str, ...]) -> List[int]:
    return [i for i, st in steps if not step_problem(st, want_keys, expected)]


def nearest_problem(steps: List[Tuple[int, Node]], want_keys: Tuple[str, ...], expected: Tuple[str, ...]) -> str:
    """The step that shares the most statements with the unit, and why it is not it."""
    best: Optional[Tuple[int, Node]] = None
    score = 0
    for i, st in steps:
        s = len(set(run_lines(st)) & set(expected))
        if s > score:
            best, score = (i, st), s
    if best is None:
        return "no step shares a statement with it"
    return f"nearest is {step_label(*best)}: {step_problem(best[1], want_keys, expected)}"


def one_unit(steps: List[Tuple[int, Node]], want_keys: Tuple[str, ...], expected: Tuple[str, ...], what: str,
             rep: Report) -> List[int]:
    found = canonical(steps, want_keys, expected)
    if len(found) != 1:
        rep.bad(f"{what} must have exactly one step with exactly the allowed body (found {len(found)})"
                + (": " + nearest_problem(steps, want_keys, expected) if not found else ""))
    return found


# ------------------------------------------------------------------ checks --
def check_no_bash_env(label: str, text: str, rep: Report) -> None:
    if "BASH_ENV" in text:
        rep.bad(f"{label}: BASH_ENV runs a file before every non-interactive bash, so it can neutralise the assert (refused anywhere)")


def check_text_counts(text: str, rep: Report) -> None:
    """Whole-file backstops (any job): at most one line builds the matrix target,
    at most one runs ``cargo ... cyclonedx``."""
    lines = logical_lines(text.split("\n"))
    builds = [ln for ln in lines if BUILD_TOOL_RE.search(ln) and "matrix.target" in ln]
    if len(builds) > 1:
        rep.bad(f"release.yml: {len(builds)} lines run a build tool against the matrix target; only the allowed unit "
                f"may build: {builds[-1][:90]}")
    sboms = [ln for ln in lines if SBOM_TOOL_RE.search(ln)]
    if len(sboms) > 1:
        rep.bad(f"release.yml: {len(sboms)} lines run `cargo ... cyclonedx`; only the SBOM unit in the `sbom:` job may: "
                f"{sboms[-1][:90]}")


def check_matrix(job: Node, rep: Report) -> None:
    st = job.get("strategy")
    matrix = st.get("matrix") if st is not None else None
    include = matrix.get("include") if matrix is not None else None
    if (st is None or set(st.keys()) != {"fail-fast", "matrix"} or st.get("fail-fast") is None
            or st.get("fail-fast").text() != "false" or matrix is None or matrix.keys() != ["include"]
            or include is None or include.kind != "seq"):
        rep.bad("release.yml release job `strategy:` must be exactly `fail-fast: false` plus `matrix:` with only "
                "`include:` entries (no other axis, no `exclude:`, no expression)")
        return
    targets: List[str] = []
    for n, entry in enumerate(include.value if isinstance(include.value, list) else []):
        keys = set(entry.keys())
        if entry.kind != "map" or not set(MATRIX_REQUIRED) <= keys <= set(MATRIX_VALUE_RE):
            rep.bad(f"release.yml release matrix entry {n + 1}: keys {sorted(keys)}; the allowed keys are "
                    f"{list(MATRIX_REQUIRED)} plus optionally `nfpm_arch`")
        for key in sorted(keys):
            val = entry.get(key)
            rx = MATRIX_VALUE_RE.get(key)
            if rx is not None and (val is None or val.style != "plain" or not rx.fullmatch(val.text())):
                rep.bad(f"release.yml release matrix entry {n + 1}: `{key}:` must be an unquoted literal matching "
                        f"`{rx.pattern}` (it is substituted into the pinned build and assert text before bash runs: "
                        "no expression, quote, space or shell metacharacter)")
        tv = entry.get("target")
        targets.append(tv.text() if tv is not None else "")
    if sorted(targets) != sorted(RELEASE_TARGETS):
        rep.bad(f"release.yml release matrix targets {sorted(targets)} differ from the pinned set "
                f"{sorted(RELEASE_TARGETS)}; if the release matrix legitimately changes, update RELEASE_TARGETS in "
                "scripts/check_release_features.py in the same commit")


def check_release_job(job: Node, rep: Report) -> None:
    if set(job.keys()) != set(JOB_KEYS):
        rep.bad(f"release.yml release job keys {job.keys()} differ from the pinned skeleton {list(JOB_KEYS)} (a job "
                "`if:`, `env:`, `defaults:`, `container:` or `continue-on-error:` can skip or neutralise the assert)")
    ro = job.get("runs-on")
    if ro is None or ro.style != "plain" or ro.text() != RELEASE_RUNS_ON:
        rep.bad(f"release.yml release job `runs-on:` must be exactly `{RELEASE_RUNS_ON}`")
    check_matrix(job, rep)
    steps = job_steps(job, "release.yml release job", rep)
    builds = one_unit(steps, KEYS_SHELL, WF_BUILD, "release.yml: the release job build", rep)
    asserts = one_unit(steps, KEYS_SHELL, WF_ASSERT, "release.yml: the release job strict assert", rep)
    if builds and asserts and min(asserts) < max(builds):
        rep.bad("release.yml: the strict assert must run after the build, in the same job")
    for i, st in steps:
        if i in builds:
            continue
        hit = next((m for m in (BUILD_TOOL_RE.search(t) for t in node_texts(st)) if m), None)
        if hit is not None:
            rep.bad(f"release.yml: release job {step_label(i, st)} runs `{hit.group(0)}`; only the canonical build "
                    "step may run a build tool in the release job (any option order or +toolchain)")


def check_sbom_job(job: Node, rep: Report) -> None:
    if set(job.keys()) != set(SBOM_JOB_KEYS):
        rep.bad(f"release.yml sbom job keys {job.keys()} differ from the pinned skeleton {list(SBOM_JOB_KEYS)}")
    one_unit(job_steps(job, "release.yml sbom job", rep), KEYS_PLAIN, WF_SBOM, "release.yml: the `sbom:` job SBOM", rep)


def check_image_build(jobs: Node, rep: Report) -> None:
    """The image the docker job ships is the Dockerfile's final stage."""
    for path, node in walk(jobs):
        if node.kind == "map" and node.get("uses") is not None and node.get("uses").text().startswith("docker/build-push-action"):
            with_ = node.get("with")
            extra = sorted(set(with_.keys()) & {"target", "file"}) if with_ is not None else []
            if extra:
                rep.bad(f"release.yml: docker/build-push-action at jobs.{'.'.join(path)} sets {extra}: the guard pins "
                        "the final stage of ./Dockerfile; another target or file ships something else")


def check_release_yml(text: str, rep: Report) -> None:
    check_no_bash_env("release.yml", text, rep)
    check_text_counts(text, rep)
    doc = parse_yaml(text, "release.yml", rep)
    if doc is None:
        return
    check_blocks(doc, "release.yml", rep)
    for key in doc.keys():
        if key not in TOP_KEYS:
            rep.bad(f"release.yml top level: `{key}:` is not allowed (allowed: {', '.join(TOP_KEYS)})")
    jobs = doc.get("jobs")
    if not want_kind(jobs, "map", "release.yml `jobs:`", rep) or jobs is None:
        return
    release, sbom = jobs.get("release"), jobs.get("sbom")
    if want_kind(release, "map", "release.yml `jobs.release`", rep) and release is not None:
        check_release_job(release, rep)
    if want_kind(sbom, "map", "release.yml `jobs.sbom`", rep) and sbom is not None:
        check_sbom_job(sbom, rep)
    check_image_build(jobs, rep)


def docker_nearest(builder: List[str]) -> str:
    want = tuple(DOCKER_RUN.split("; "))
    runs = [ins for ins in builder if ins.upper().startswith("RUN ")]
    if not runs:
        return "the builder stage has no RUN"
    got = max(runs, key=lambda r: len(set(r.split("; ")) & set(want)))
    return "nearest builder RUN: " + first_diff(tuple(got.split("; ")), want)


def check_dockerfile(text: str, rep: Report) -> None:
    check_no_bash_env("Dockerfile", text, rep)
    raw = text.split("\n")
    if raw[0] != DOCKER_SYNTAX:
        rep.bad(f"Dockerfile: line 1 must be exactly `{DOCKER_SYNTAX}` (the syntax directive picks the frontend that "
                f"parses the file): {raw[0][:60]}")
    for n, ln in enumerate(raw[1:], 2):
        if DIRECTIVE_RE.match(ln):
            rep.bad(f"Dockerfile: line {n}: a parser directive other than the pinned line-1 syntax (an `escape` "
                    f"directive changes what a line continuation is): {ln.strip()[:60]}")
    stages: List[Tuple[Optional[str], List[str]]] = []
    names: Dict[str, int] = {}
    for ins in logical_lines(raw):
        word = ins.split(" ", 1)[0].upper()
        if "<<" in ins:
            rep.bad(f"Dockerfile: heredoc (`<<`) refused, the guard cannot see what it runs: {ins[:60]}")
        if word not in DOCKER_INSTRUCTIONS:
            rep.bad(f"Dockerfile: `{word}` refused (SHELL swaps the shell of the build RUN; ONBUILD and unknown "
                    f"instructions are outside the subset): {ins[:60]}")
            continue
        if word == "FROM":
            m = FROM_RE.fullmatch(ins)
            if m is None:
                rep.bad(f"Dockerfile: FROM outside `FROM [--platform=x] image [AS name]`: {ins[:80]}")
                toks = ins.split(" ")
                image, name = (toks[1] if len(toks) > 1 else ""), None
            else:
                image, name = m.group("image"), m.group("name")
            if image.lower() in names:
                rep.bad(f"Dockerfile: `{ins[:60]}` starts a stage FROM an earlier stage (a stage starts from a base image)")
            if name is not None:
                if name.lower() in names:
                    rep.bad(f"Dockerfile: duplicate stage name `{name}`")
                names.setdefault(name.lower(), len(stages))
            stages.append((name, []))
            continue
        if not stages:
            if word != "ARG":
                rep.bad(f"Dockerfile: `{word}` before the first FROM: {ins[:60]}")
            continue
        stages[-1][1].append(ins)
    final = stages[-1][1] if stages else []
    copies = [m.group("stage").lower() for m in (BINARY_COPY_RE.fullmatch(i) for i in final) if m]
    if len(copies) != 1:
        rep.bad("Dockerfile: the final stage must COPY the binary exactly once: "
                "`COPY --from=<stage> /build/target/release/ai-memory /usr/local/bin/ai-memory`")
    src = copies[0] if copies else ""
    for ins in final:
        m = FROM_FLAG_RE.search(ins)
        if m is not None and m.group("src").lower() != src:
            rep.bad(f"Dockerfile: final-stage `{ins[:60]}` takes `--from={m.group('src')}`; only the stage that "
                    "builds the binary may feed the image")
    bidx = names.get(src)
    if bidx is None or bidx == len(stages) - 1:
        rep.bad(f"Dockerfile: the final image copies the binary from `{src}`, which is not an earlier named stage")
        return
    for k, (_, body) in enumerate(stages):
        for pos, ins in enumerate(body):
            canon = k == bidx and pos == len(body) - 1 and ins == DOCKER_RUN
            if BUILD_TOOL_RE.search(ins) and not canon:
                rep.bad(f"Dockerfile: a build tool outside the canonical build RUN (the last instruction of the stage the "
                        f"image copies the binary from): {ins[:80]}")
    builder = stages[bidx][1]
    for ins in builder:
        if FROM_FLAG_RE.search(ins):
            rep.bad(f"Dockerfile: the builder stage takes `--from` another stage or image: {ins[:60]}")
    if DOCKER_LOCK_COPY not in builder[:-2]:
        rep.bad(f"Dockerfile: the builder stage does not `{DOCKER_LOCK_COPY}` before the build")
    if builder[-2:-1] != [DOCKER_DECL_COPY]:
        rep.bad(f"Dockerfile: the builder stage must `{DOCKER_DECL_COPY}` immediately before the build RUN")
    if builder[-1:] != [DOCKER_RUN]:
        rep.bad("Dockerfile: the builder stage must END with exactly the allowed build+assert RUN (nothing after it); "
                + docker_nearest(builder))


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
    doc = parse_yaml(text, "release-shape.yml", rep)
    if doc is None:
        return
    check_blocks(doc, "release-shape.yml", rep)
    jobs = doc.get("jobs")
    job = jobs.get("release-shape") if jobs is not None else None
    if want_kind(job, "map", "release-shape.yml `jobs.release-shape`", rep) and job is not None:
        one_unit(job_steps(job, "release-shape.yml release-shape job", rep), KEYS_SHELL, SHAPE_BUILD,
                 "release-shape.yml: the `release-shape:` job build", rep)


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


NEEDS_REL = "    needs: [preflight, qualify, supply-chain]\n    runs-on: ${{ matrix.os }}\n"
MATRIX_FF = "      fail-fast: false\n"
ENTRY1 = "          - target: x86_64-unknown-linux-gnu\n            os: ubuntu-latest\n            artifact: ai-memory\n"
SBOM_JOB = "  sbom:\n    name: SBOM (CycloneDX)\n"
PUSH_WITH = "        with:\n          context: .\n"
D_BUILDER = "FROM rust:1.98-slim-bookworm AS builder\n"
D_FINAL = "FROM debian:bookworm-slim\n"
D_WORKDIR = "WORKDIR /build\n"
D_LOCK = DOCKER_LOCK_COPY + "\n"
D_BIN = "COPY --from=builder /build/target/release/ai-memory /usr/local/bin/ai-memory\n"
SHAPE_JOB = "\n  release-shape:\n"


def _docker(old: str, new: Union[str, Transform], every: bool = False) -> Edit:
    return (DOCKER, old, new, every)


def _step_before_pkg(body: str) -> List[Edit]:
    """A new release-job step (after the strict assert)."""
    return [_rel(PKG_HDR, "      - name: extra\n" + body + PKG_HDR)]


def _append_job(body: str) -> Transform:
    return lambda t: t.rstrip("\n") + "\n\n  decoy:\n    runs-on: ubuntu-latest\n    steps:\n" + body


def _move_sbom_to_decoy(text: str) -> str:
    a = text.index(SBOM_HDR)
    b = text.index("      - name:", a + len(SBOM_HDR))
    block = text[a:b]
    return _append_job(block)(text[:a] + text[b:])


def _dead_stage_then_alter(text: str) -> str:
    """D1: a dead stage holds the canonical RUN while the shipped builder changes."""
    a, b = text.index(D_BUILDER), text.index(D_FINAL)
    dead = text[a:b].replace(" AS builder", " AS decoy")
    live = text[a:b].replace("strip target/release/ai-memory", "true")
    return text[:a] + dead + live + text[b:]


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
    # --- #4719 SR-1/H1/M1: structural location, exact indentation (YAML subset)
    "SR1 trailing tab after the assert statement": ("fail", [_rel(REL_ASSERT, REL_ASSERT + "\t")]),
    "SR1/J1 job key at indent 5 (multi-line scalar or stray key)": ("fail", [_rel(JOB_NAME, JOB_NAME + "     if: false\n")]),
    "SR1/J2 continuation line of a plain job name": ("fail", [_rel(JOB_NAME, JOB_NAME + "      continued\n")]),
    "SR1 step-level key written with quotes": ("fail", [_rel(REL_ASSERT, REL_ASSERT + "\n        \"if\": false")]),
    "SR1 anchor on a job value": ("fail", [_rel(NEEDS_REL, NEEDS_REL.replace("needs: [", "needs: &n ["))]),
    "SR1 alias as a job value": ("fail", [_rel(NEEDS_REL, NEEDS_REL + "    timeout-minutes: *n\n")]),
    "SR1 tag on a job value": ("fail", [_rel(NEEDS_REL, NEEDS_REL.replace("needs: [", "needs: !!seq ["))]),
    "SR1 flow mapping value": ("fail", [_rel(NEEDS_REL, NEEDS_REL + "    env: {A: b}\n")]),
    "SR1 multi-line double-quoted value": ("fail", [_rel(JOB_NAME, '    name: "Release\n      x"\n')]),
    "SR1 block indentation indicator": ("fail", [_rel(JOB_NAME, "    name: |2\n      Release\n")]),
    "SR1 sequence line more indented than its items": ("fail", [_rel(PKG_HDR, "       - name: stray\n" + PKG_HDR)]),
    "SR1/J3 block scalar as the job name": ("fail", [_rel(JOB_NAME, "    name: |\n      Release (${{ matrix.target }})\n")]),
    "SR1/J3 folded block as a step if": ("fail", _hdr_key(ASSERT_NAME, "if: >-\n          true")),
    "SR1 release job runs-on changed": ("fail", [_rel(NEEDS_REL, NEEDS_REL.replace("${{ matrix.os }}", "self-hosted"))]),
    "SR1 release job if: (skips the job)": ("fail", [_rel(JOB_NAME, JOB_NAME + "    if: false\n")]),
    "SR1 release job container:": ("fail", [_rel(JOB_NAME, JOB_NAME + "    container: decoy:latest\n")]),
    "SR1 a step is a plain scalar, not a mapping": ("fail", [_rel(PKG_HDR, "      - echo hi\n" + PKG_HDR)]),
    "SR1 build step name carries an expression": ("fail", [_rel(BUILD_HDR, BUILD_HDR.replace("binary", "binary ${{ matrix.os }}"))]),
    "SR1 run: |- on the assert step": ("fail", [_rel(ASSERT_RUN, ASSERT_RUN.replace("run: |", "run: |-"))]),
    "SR1 jobs: is not a mapping": ("fail", [_rel("\njobs:\n", "\njobs: []\nx-jobs:\n")]),
    "valid: comment lines inside the release job and a matrix entry": ("pass", [_rel(
        NEEDS_REL, NEEDS_REL + "    # a comment\n"), _rel(ENTRY1, ENTRY1.replace("            os:", "            # c\n            os:"))]),
    # --- #4719 SR-2/H2: matrix values substituted into the pinned units
    "SR2 strategy fail-fast: true": ("fail", [_rel(MATRIX_FF, "      fail-fast: true\n")]),
    "SR2 matrix gains an axis": ("fail", [_rel(MATRIX_FF + "      matrix:\n", MATRIX_FF + "      matrix:\n        x: [a]\n")]),
    "SR2 matrix entry gains a key": ("fail", [_rel(ENTRY1, ENTRY1 + "            runner: x\n")]),
    "SR2/J4 artifact quoted": ("fail", [_rel(ENTRY1, ENTRY1.replace("artifact: ai-memory", "artifact: 'ai-memory'"))]),
    "SR2/J4 artifact carries shell": ("fail", [_rel(ENTRY1, ENTRY1.replace("artifact: ai-memory", "artifact: ai-memory;true"))]),
    "SR2/J4 target carries a substitution": ("fail", [_rel(
        ENTRY1, ENTRY1.replace("x86_64-unknown-linux-gnu", "x86_64-unknown-linux-gnu$(true)"))]),
    "SR2/J4 os is an expression": ("fail", [_rel(ENTRY1, ENTRY1.replace("ubuntu-latest", "${{ github.event.inputs.tag }}"))]),
    "SR2 a valid target outside the pinned set": ("fail", [_rel(
        ENTRY1, ENTRY1.replace("x86_64-unknown-linux-gnu", "riscv64gc-unknown-linux-gnu"))]),
    "SR2 a matrix entry dropped": ("fail", [_rel(ENTRY1 + "            nfpm_arch: amd64\n", "")]),
    # --- #4719 L1: no other building cargo in the release job
    "L1/J6 cargo -q build in a later release step": ("fail", _step_before_pkg("        run: cargo -q build --release\n")),
    "L1/J6 CARGO build (case-insensitive file system)": ("fail", _step_before_pkg("        run: CARGO build --release\n")),
    "L1/J6 cargo --config before the subcommand": ("fail", _step_before_pkg("        run: cargo --config x=y build\n")),
    "L1/J6 cross build in a later step": ("fail", _step_before_pkg("        run: |\n          cross build --release\n")),
    "L1/J6 rustc in a later step": ("fail", _step_before_pkg("        run: rustc -O src/main.rs\n")),
    "L1/J6 a cargo action in a later step": ("fail", _step_before_pkg("        uses: actions-rs/cargo@v1\n")),
    "L1 second matrix-target build in another job": ("fail", [_rel(
        SBOM_HDR, "      - name: x\n        run: cargo build --target ${{ matrix.target }}\n" + SBOM_HDR)]),
    "L1 image build picks another stage": ("fail", [_rel(PUSH_WITH, PUSH_WITH + "          target: builder\n")]),
    # --- #4719 L6: the SBOM unit lives in the sbom: job
    "L6/J5 SBOM step moved to a decoy job": ("fail", [_rel(SBOM_HDR, _move_sbom_to_decoy)]),
    "L6/J5 SBOM copied into a decoy job": ("fail", [_rel(
        SBOM_HDR, _append_job("      - name: x\n        run: cargo cyclonedx --format json --features sal\n"))]),
    "L6 sbom job carries an if": ("fail", [_rel(SBOM_JOB, SBOM_JOB + "    if: false\n")]),
    "release-shape build job renamed": ("fail", [(SHAPE, SHAPE_JOB, "\n  release-shape-x:\n", False)]),
    # --- #4719 SR-3/M2: Dockerfile directives, heredocs, stage chain
    "SR3 syntax directive changed": ("fail", [_docker(DOCKER_SYNTAX + "\n", "# syntax=docker/dockerfile:1.7\n")]),
    "SR3 escape directive": ("fail", [_docker(DOCKER_SYNTAX + "\n", DOCKER_SYNTAX + "\n# escape=`\n")]),
    "SR3 heredoc RUN in the final stage": ("fail", [_docker(D_BIN, D_BIN + "RUN cat <<<x\n")]),
    "SR3 ONBUILD instruction": ("fail", [_docker(D_BIN, D_BIN + "ONBUILD RUN true\n")]),
    "SR3 unknown instruction": ("fail", [_docker(D_BIN, D_BIN + "BOGUS x\n")]),
    "SR3 instruction before the first FROM": ("fail", [_docker(D_BUILDER, "ENV X=1\n" + D_BUILDER)]),
    "SR3 FROM outside the subset": ("fail", [_docker(D_FINAL, "FROM busybox junk AS dead\n" + D_FINAL)]),
    "SR3 stage FROM an earlier stage": ("fail", [_docker(D_FINAL, "FROM builder AS other\n" + D_FINAL)]),
    "SR3 duplicate stage name": ("fail", [_docker(D_FINAL, "FROM busybox AS builder\n" + D_FINAL)]),
    "SR3 binary copied twice": ("fail", [_docker(D_BIN, D_BIN + D_BIN)]),
    "SR3 final stage takes another --from": ("fail", [_docker(D_BIN, D_BIN + "COPY --from=busybox /bin/sh /bin/sh2\n")]),
    "SR3 binary copied from an image, not a stage": ("fail", [_docker(D_BIN, D_BIN.replace("=builder", "=rust:1.98"))]),
    "SR3 builder takes a --from": ("fail", [_docker(D_WORKDIR, D_WORKDIR + "COPY --from=busybox /bin/sh /bin/sh\n")]),
    "SR3/D1 dead stage holds the canonical RUN, shipped builder altered": ("fail", [_docker(D_BUILDER, _dead_stage_then_alter)]),
    "SR3 cargo fetch in the builder before the canonical RUN": ("fail", [_docker(D_LOCK, D_LOCK + "RUN cargo fetch\n")]),
    "SR3 instruction between the declaration COPY and the RUN": ("fail", [_docker(DOCKER_RUN_HEAD, "ENV X=1\n" + DOCKER_RUN_HEAD)]),
    "SR3 build dropped from the builder RUN (no build tool left)": ("fail", [_docker(DOCKER_BUILD, "true; \\")]),
    "SR3 RUN appended after the canonical RUN": ("fail", [_docker(D_FINAL, "RUN true\n" + D_FINAL)]),
    # --- #4719 L2: non-ASCII spaces and zero-width characters are refused, never folded
    "L2/D2 NBSP inside the build statement": ("fail", [_rel(REL_BUILD_CMD, REL_BUILD_CMD.replace("cargo build", "cargo\u00a0build"))]),
    "L2/D3 em space in the Dockerfile RUN": ("fail", [_docker(DOCKER_ASSERT, DOCKER_ASSERT.replace(" --strict", "\u2003--strict"))]),
    "L2 zero-width space in release-shape.yml": ("fail", [(SHAPE, SHAPE_BUILD_CMD, SHAPE_BUILD_CMD.replace("cargo", "car\u200bgo"), False)]),
    "L2 bare CR inside a comment line (a YAML line break) hides a job key": ("fail", [_rel(
        JOB_NAME, JOB_NAME + "    # note\r    if: false\n")]),
    "L2 U+2028 inside a comment line (a YAML 1.1 line break) hides a job key": ("fail", [_rel(
        JOB_NAME, JOB_NAME + "    # note\u2028    if: false\n")]),
    "L2 byte-order mark at the start of release.yml": ("fail", [_rel(JOB_NAME, lambda t: "\ufeff" + t)]),
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
