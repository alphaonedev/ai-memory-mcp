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
ships are compared to their EXACT expected text, after normalising only runs
of spaces/tabs; anything else is refused. Line continuations are not modelled:
a run line ending in ``\\`` is refused in release.yml and release-shape.yml, and
in the Dockerfile the ONLY continued lines allowed are those of the canonical
build RUN, which is compared physical line by physical line
(``DOCKER_RUN_LINES``). The units are:

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
    (and the other build tools) anywhere else in the Dockerfile is refused, read
    with quote and backslash characters removed. Every line ending in ``\\``
    outside the canonical RUN is refused, and the canonical RUN's lines must be
    exactly ``DOCKER_RUN_LINES`` (no comment or blank line inside, no re-indent).
    A ``FROM`` image containing ``$`` is refused (a build-arg base the guard
    cannot resolve), and ``--mount`` is refused anywhere in an instruction (a
    mount can import files the guard never read). Instructions are split as
    BuildKit splits them (``bk_instructions``: a ``\\`` with only spaces/tabs
    after it continues, the next line is appended as written). That join is
    checked against recorded parser outputs (the PARITY table, from the
    moby/buildkit v0.23.2 parser) and a differential fuzz, but the guard does
    not RELY on it matching every BuildKit input: it refuses every continuation
    it would have to join, except the one pinned line by line.
  * The ``docker:`` job is pinned WHOLE, because it holds ``packages: write``:
    its keys are exactly ``name``/``needs``/``if``/``runs-on``/``permissions``/
    ``steps`` with pinned values (``DOCKER_JOB``; a job ``env:``, ``container:``,
    ``defaults:``, ``services:`` or ``strategy:`` is refused), and its steps are
    exactly the pinned ordered list (``DOCKER_STEPS``: checkout, Buildx setup,
    registry login, version, image build, provenance attestation), each with its
    exact keys, its ``uses`` pinned to a SHA constant, its ``with:`` inputs and
    its run text. No step can be added, removed, reordered or changed.
  * Permissions, secrets and the registry. The top-level ``permissions:`` is
    exactly ``contents: write`` and every job's ``permissions:`` is pinned
    (``RELEASE_JOB_PERMISSIONS``; ``packages: write`` exists in the docker job
    only); the job set is pinned and no job may call a reusable workflow. Every
    ``secrets`` reference must be ``secrets.<NAME>`` with NAME in
    ``RELEASE_SECRETS`` and no key may be named ``secrets``. The registry host
    (``ghcr.io``, any case) may appear only inside the docker job.
  * Quoting. A double-quoted YAML scalar containing a backslash is refused (YAML
    decodes escapes such as ``\\x63`` that this parser would read raw); a
    single-quoted ``''`` is decoded to ``'`` as YAML does. The build-tool scans
    (release job, whole release.yml, Dockerfile) read the text with quote and
    backslash characters removed (``c''argo`` reads as ``cargo``). That is a
    best-effort spelling view for REFUSALS only; it cannot see a name built by
    expansion (#4752, #4768).
  * release-shape.yml is pinned as a skeleton: its top-level keys in order
    (``SHAPE_TOP_KEYS``), the ``on:`` triggers (``SHAPE_ON``, branch and path
    filters included), ``permissions:`` (``SHAPE_PERMISSIONS``) and ``env:``
    (exactly the two ``CARGO_*`` values, ``SHAPE_ENV``); exactly one job,
    ``release-shape:``, whose keys are exactly ``name``/``runs-on``/
    ``timeout-minutes``/``steps`` with pinned values (``SHAPE_JOB``), so no job
    ``needs:``, ``if:``, ``env:``, ``defaults:``, ``container:`` or
    ``services:``. ``continue-on-error`` follows ``SHAPE_ADVISORY``: while it is
    True (the #4480 ruling: advisory until the first green run on main) the job
    must carry exactly the plain ``continue-on-error: true``; when #4720 flips it
    to False the key is refused. The Postgres proof is located structurally:
    exactly one ``run`` step whose statements equal the pinned
    ``bash scripts/release-shape-pg-proof.sh target/release/ai-memory "$url"``
    (the URL assignment may change its port only), with the step key set pinned
    (so no step ``if:`` or ``continue-on-error:``), ordered after the
    release-shaped build. The ``paths:`` trigger filter is NOT evidence.

PIN MAINTENANCE. Every pin-mismatch message names the constant to update and
this file. A Dependabot SHA bump of a docker-job action fails with ONE message
naming its ``*_USES`` constant: update that constant to the new SHA in the same
commit (the rest of the step is still compared). Any other intended change to a
pinned unit is made the same way, in the workflow and here, in one commit.

Whole-line comments are dropped; a trailing ``#`` is NOT trusted (the statement
then differs from the allowed one and is refused). ``BASH_ENV`` is refused
anywhere in release.yml, release-shape.yml and the Dockerfile. Control
characters (CR, form feed, NUL...), NBSP and every other Unicode space or zero-width character in the
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
# The ONLY `\` continuation the guard accepts anywhere: the canonical build RUN,
# compared physical line by physical line (#4719 C-1/C-2). Any other line that
# ends in `\` (Dockerfile, or release.yml / release-shape.yml run text) is refused.
DOCKER_RUN_LINES = (
    "RUN set -eu; \\",
    "    " + ALLOWED_FEATURES + "; \\",
    "    " + ALLOWED_REQUIRE + "; \\",
    '    test -n "$FEATURES"; \\',
    '    test -n "$REQUIRE_FLAGS"; \\',
    "    " + SHAPE_BUILD_CMD + "; \\",
    "    strip target/release/ai-memory; \\",
    "    " + ASSERT_DOCKER,
)
SHAPE_PROOF_CMD = 'bash scripts/release-shape-pg-proof.sh target/release/ai-memory "$url"'
SHAPE_PROOF_URL = "url=<the TLS verify-full proof URL>"
SHAPE_PROOF = ("set -euo pipefail", SHAPE_PROOF_URL, SHAPE_PROOF_CMD)
SHAPE_URL_RE = re.compile(
    r'url="postgres://postgres:\$\{PGTLS_PW\}@127\.0\.0\.1:[0-9]+/proof\?sslmode=verify-full'
    r'&sslrootcert=\$\{PGTLS_DIR\}/ca\.crt"')
GUARD_PATH = "scripts/check_release_features.py"


class Flow(str):
    """A pinned flow-sequence value, compared by its text between the brackets."""


class Double(str):
    """A pinned double-quoted scalar (no backslash: the parser refuses one)."""


class Block(tuple):
    """A pinned ``|`` literal block, compared line by line."""


# Pinned YAML: str = plain scalar, Flow / Double = that style, Block = `|` lines,
# dict = a mapping with exactly these keys, list = a sequence of exactly these
# items, None = a key with no value.
Spec = Union[str, Flow, Double, Block, Dict[str, object], List[object], None]

# The docker job is pinned WHOLE (#4719 SR-8/SR-9): it holds `packages: write`,
# so anything it runs can put an image on the release tag. Every action is pinned
# to its SHA; a Dependabot bump of one of these SHAs fails with one message that
# names the constant to update.
CHECKOUT_USES = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
BUILDX_USES = "docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f"
LOGIN_USES = "docker/login-action@c94ce9fb468520275223c153574b00df6fe4bcc9"
IMAGE_BUILD_USES = "docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8"
ATTEST_USES = "actions/attest-build-provenance@e8998f949152b193b063cb0ec769d69d929409be"
USES_CONSTANTS = {
    CHECKOUT_USES: "CHECKOUT_USES",
    BUILDX_USES: "BUILDX_USES",
    LOGIN_USES: "LOGIN_USES",
    IMAGE_BUILD_USES: "IMAGE_BUILD_USES",
    ATTEST_USES: "ATTEST_USES",
}
DOCKER_JOB: Dict[str, Spec] = {
    "name": "Docker (GHCR)",
    "needs": Flow("preflight, qualify, supply-chain"),
    "if": "needs.preflight.outputs.is_prerelease == 'false'",
    "runs-on": "ubuntu-latest",
    "permissions": {"contents": "read", "packages": "write", "id-token": "write", "attestations": "write"},
}
DOCKER_STEPS: List[Spec] = [
    {"uses": CHECKOUT_USES, "with": {"ref": "${{ needs.preflight.outputs.sha }}"}},
    {"name": "Set up Docker Buildx", "uses": BUILDX_USES},
    {"name": "Log in to GitHub Container Registry", "uses": LOGIN_USES,
     "with": {"registry": "ghcr.io", "username": "${{ github.actor }}", "password": "${{ secrets.GITHUB_TOKEN }}"}},
    {"name": "Extract version from tag", "id": "version", "run": 'echo "version=${TAG#v}" >> "$GITHUB_OUTPUT"',
     "env": {"TAG": "${{ needs.preflight.outputs.tag }}"}},
    {"name": "Build and push Docker image", "id": "build", "uses": IMAGE_BUILD_USES, "with": {
        "context": ".",
        "push": "${{ github.event.inputs.dry_run == 'false' }}",
        "tags": Block((
            "ghcr.io/${{ github.repository_owner }}/ai-memory:${{ steps.version.outputs.version }}",
            "ghcr.io/${{ github.repository_owner }}/ai-memory:latest",
        )),
        "labels": Block((
            "org.opencontainers.image.source=https://github.com/${{ github.repository }}",
            "org.opencontainers.image.version=${{ steps.version.outputs.version }}",
        )),
        "cache-from": "type=gha",
        "cache-to": "type=gha,mode=max",
    }},
    {"name": "Attest build provenance (Docker image)", "if": "github.event.inputs.dry_run == 'false'",
     "uses": ATTEST_USES, "with": {
         "subject-name": "ghcr.io/${{ github.repository_owner }}/ai-memory",
         "subject-digest": "${{ steps.build.outputs.digest }}",
         "push-to-registry": "true",
     }},
]
# What each pinned docker step is, for the messages.
DOCKER_STEP_ROLES = ("checkout", "Buildx setup", "registry login", "version", "image build", "provenance attestation")
# release.yml permissions, pinned per job (#4719 SR-8): `packages: write` exists in
# the docker job only; None = the job declares none and inherits the top level.
RELEASE_TOP_PERMISSIONS: Dict[str, Spec] = {"contents": "write"}
_SIGN = {"contents": "write", "id-token": "write", "attestations": "write"}
_READ_ATTEST = {"contents": "read", "attestations": "read"}
RELEASE_JOB_PERMISSIONS: Dict[str, Optional[Dict[str, Spec]]] = {
    "preflight": {"contents": "read"},
    "qualify": {"contents": "read", "checks": "read", "actions": "read"},
    "supply-chain": None,
    "release": dict(_SIGN),
    "sbom": dict(_SIGN),
    "mobile-ios": dict(_SIGN),
    "mobile-android": dict(_SIGN),
    "crates-io": None,
    "homebrew": dict(_READ_ATTEST),
    "docker": dict(DOCKER_JOB["permissions"]),  # type: ignore[arg-type]
    "copr": dict(_READ_ATTEST),
}
# The only secrets release.yml may read: a new credential (a registry token in
# another job) is refused until it is added here on purpose.
RELEASE_SECRETS = ("GITHUB_TOKEN", "CARGO_REGISTRY_TOKEN", "HOMEBREW_TAP_TOKEN", "COPR_CONFIG")
SECRET_REF_RE = re.compile(r"(?<![\w.-])secrets(?![\w-])(?P<ref>\s*\.\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*))?", re.I)
# The image registry is named only inside the pinned docker job.
REGISTRY = "ghcr.io"
# release-shape.yml skeleton (#4719 SR-10).
SHAPE_TOP_KEYS = ("name", "on", "permissions", "concurrency", "env", "jobs")
SHAPE_PERMISSIONS: Dict[str, Spec] = {"contents": "read"}
SHAPE_ENV: Dict[str, Spec] = {"CARGO_TERM_COLOR": "always", "CARGO_INCREMENTAL": Double("0")}
SHAPE_PATHS = (
    ".github/workflows/release.yml", ".github/workflows/release-shape.yml", "scripts/release-features.sh",
    "scripts/check_release_features.py", "scripts/release-shape-pg-proof.sh", "scripts/assert-compiled-features.sh",
    "Cargo.toml", "Cargo.lock", "src/**", "migrations/**",
)
SHAPE_ON: Dict[str, Spec] = {
    "pull_request": {"branches": Flow('"release/**", "rehearsal/**", "main"'), "paths": [Double(p) for p in SHAPE_PATHS]},
    "push": {"branches": Flow('"release/**"')},
    "workflow_dispatch": None,
}
SHAPE_JOB: Dict[str, Spec] = {
    "name": Double("Release-shaped build + PG TLS proof"),
    "runs-on": "ubuntu-latest",
    "timeout-minutes": "60",
}
# #4480 ruled the release-shape job ADVISORY until its first green run on main; #4720
# tracks the flip to required. While True the job must carry exactly the plain
# `continue-on-error: true`; the #4720 fix sets this to False in the same commit
# that drops the key from release-shape.yml, after which the key is refused.
SHAPE_ADVISORY = True
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
RELEASE_JOBS = tuple(RELEASE_JOB_PERMISSIONS)
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
# Quote and backslash characters bash removes inside a word (`c''argo`, `ca\rgo`).
QUOTE_RE = re.compile(r"['\"\\]")
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
BK_CONT_RE = re.compile(r"(^|[^\\])\\[ \t]*$")  # BuildKit lineContinuationRegex for the default escape `\`
DIRECTIVE_RE = re.compile(r"^[ \t]*#[ \t]*(?:syntax|escape|check)[ \t]*=", re.I)


# ------------------------------------------------------------ text helpers --
def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def is_blank_or_comment(line: str) -> bool:
    s = line.strip(" \t")
    return not s or s.startswith("#")


def _collapse(text: str) -> str:
    """Runs of spaces/tabs collapsed, ends stripped (ONLY spaces and tabs: any
    other Unicode space is refused by CONTROL_RE, never folded)."""
    return re.sub(r"[ \t]+", " ", text).strip(" ")


def bk_instructions(lines: List[str]) -> List[Tuple[int, int, str]]:
    """The BuildKit (v0.23 parser) instructions of a Dockerfile as (first line,
    last line, text), 1-based. A physical line continues iff it matches
    BK_CONT_RE; the ``\\`` and its trailing spaces/tabs are removed and the next
    line is appended AS WRITTEN (its leading whitespace kept, so ``RUN ca\\`` +
    ``rgo`` is ``RUN cargo``). Inside a continuation a whole-line comment is
    dropped and a blank line skipped; outside one both are skipped. End of file
    inside a continuation emits what was read, even when it is empty, as
    BuildKit does. The text is then collapsed."""
    out: List[Tuple[int, int, str]] = []
    buf: Optional[str] = None
    start = 0
    for n, raw in enumerate(lines, 1):
        s = raw.strip(" \t")
        if not s or s.startswith("#"):
            continue
        if buf is None:
            start, piece = n, raw.lstrip(" \t")
        else:
            piece = raw
        m = BK_CONT_RE.search(piece)
        if m is not None:
            buf = (buf or "") + piece[: m.start()] + m.group(1)
            continue
        out.append((start, n, _collapse((buf or "") + piece)))
        buf = None
    if buf is not None:
        out.append((start, len(lines), _collapse(buf)))
    return out


def logical_lines(lines: List[str], buildkit: bool = False) -> List[str]:
    """Normalise to logical lines, collapsed (see _collapse). NOTHING else is
    interpreted: a trailing ``#`` stays in the line.

    DOCKERFILE text (``buildkit=True``) is joined exactly as BuildKit joins it
    (bk_instructions). SHELL text (``buildkit=False``) is joined as bash joins
    it: only a line ending in an ODD number of backslashes with nothing after
    them continues; one backslash is removed and the next line is appended as
    written. Outside a continuation whole-line comments and blanks are dropped;
    inside one a comment line is KEPT (it can only add refusals) and a blank
    line ends the command. The guard refuses every continued line outside the
    canonical Dockerfile RUN, so these joins only have to be exact, not lenient."""
    if buildkit:
        return [text for _, _, text in bk_instructions(lines)]
    out: List[str] = []
    buf: Optional[str] = None
    for raw in lines:
        s = raw.strip(" \t")
        if buf is None and (not s or s.startswith("#")):
            continue
        if buf is not None and not s:
            if _collapse(buf):
                out.append(_collapse(buf))
            buf = None
            continue
        cur = (buf or "") + raw
        if (len(raw) - len(raw.rstrip("\\"))) % 2 == 1:
            buf = cur[:-1]
            continue
        out.append(_collapse(cur))
        buf = None
    if buf is not None and _collapse(buf):
        out.append(_collapse(buf))
    return out


def continued_lines(lines: List[str]) -> List[int]:
    """1-based numbers of the lines that end in ``\\`` (trailing spaces/tabs
    ignored): every one a reader might join to the next line."""
    return [n for n, raw in enumerate(lines, 1) if raw.rstrip(" \t").endswith("\\")]


def continuation_noise(lines: List[str]) -> List[int]:
    """1-based numbers of the blank and whole-line comment lines that sit inside an
    open BuildKit continuation (BuildKit drops them silently). Used by the parity
    self-checks; the guard itself refuses the continuation."""
    noise: List[int] = []
    open_ = False
    for n, raw in enumerate(lines, 1):
        s = raw.strip(" \t")
        if not s or s.startswith("#"):
            if open_:
                noise.append(n)
            continue
        open_ = BK_CONT_RE.search(raw) is not None
    return noise


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
                v = m.group("v")
                if style == "double" and "\\" in v:
                    self.bad(j, "a backslash inside a double-quoted scalar (YAML decodes escapes such as \\x63 or \\u0063 "
                                f"that the guard would read raw; refused, never decoded): {val[:60]}")
                if style == "single":
                    return Node("scalar", j, v[1:-1].replace("''", "'"), style)
                return Node("scalar", j, v if style == "plain" else v[1:-1], style)
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


Norm = Callable[[Tuple[str, ...]], Tuple[str, ...]]


def _same(lines: Tuple[str, ...]) -> Tuple[str, ...]:
    return lines


def step_problem(step: Node, want_keys: Tuple[str, ...], expected: Tuple[str, ...], norm: Norm = _same) -> str:
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
    got = norm(run_lines(step))
    if got != expected:
        why.bad(first_diff(got, expected))
    return why.first()


def job_steps(job: Node, where: str, rep: Report) -> List[Tuple[int, Node]]:
    steps = job.get("steps")
    if steps is None or steps.kind != "seq" or not isinstance(steps.value, list):
        return []
    return [(i, st) for i, st in enumerate(steps.value) if want_kind(st, "map", f"{where} step {i + 1}", rep)]


def canonical(steps: List[Tuple[int, Node]], want_keys: Tuple[str, ...], expected: Tuple[str, ...],
              norm: Norm = _same) -> List[int]:
    return [i for i, st in steps if not step_problem(st, want_keys, expected, norm)]


def nearest_problem(steps: List[Tuple[int, Node]], want_keys: Tuple[str, ...], expected: Tuple[str, ...],
                    norm: Norm = _same) -> str:
    """The step that shares the most statements with the unit, and why it is not it."""
    best: Optional[Tuple[int, Node]] = None
    score = 0
    for i, st in steps:
        s = len(set(norm(run_lines(st))) & set(expected))
        if s > score:
            best, score = (i, st), s
    if best is None:
        return "no step shares a statement with it"
    return f"nearest is {step_label(*best)}: {step_problem(best[1], want_keys, expected, norm)}"


def one_unit(steps: List[Tuple[int, Node]], want_keys: Tuple[str, ...], expected: Tuple[str, ...], what: str,
             rep: Report, const: str, norm: Norm = _same) -> List[int]:
    found = canonical(steps, want_keys, expected, norm)
    if len(found) != 1:
        rep.bad(f"{what} must have exactly one step with exactly the allowed body (found {len(found)})"
                + (": " + nearest_problem(steps, want_keys, expected, norm) if not found else "") + pin_hint(const))
    return found


# ------------------------------------------------------------------ checks --
def check_no_bash_env(label: str, text: str, rep: Report) -> None:
    if "BASH_ENV" in text:
        rep.bad(f"{label}: BASH_ENV runs a file before every non-interactive bash, so it can neutralise the assert (refused anywhere)")


def unquoted(text: str) -> str:
    """``text`` as bash reads a word: quote and backslash characters removed
    (``c''argo`` and ``ca\\rgo`` read as ``cargo``). A best-effort spelling view
    for REFUSALS only; it cannot see a name built by expansion."""
    return QUOTE_RE.sub("", text)


def check_text_counts(text: str, rep: Report) -> None:
    """Whole-file backstops (any job): at most one line builds the matrix target,
    at most one runs ``cargo ... cyclonedx``."""
    lines = logical_lines(text.split("\n"))
    builds = [ln for ln in lines if BUILD_TOOL_RE.search(unquoted(ln)) and "matrix.target" in ln]
    if len(builds) > 1:
        rep.bad(f"release.yml: {len(builds)} lines run a build tool against the matrix target; only the allowed unit "
                f"may build: {builds[-1][:90]}")
    sboms = [ln for ln in lines if SBOM_TOOL_RE.search(unquoted(ln))]
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
                "`include:` entries (no other axis, no `exclude:`, no expression; the shape is fixed in check_matrix in "
                f"{GUARD_PATH})")
        return
    targets: List[str] = []
    for n, entry in enumerate(include.value if isinstance(include.value, list) else []):
        keys = set(entry.keys())
        if entry.kind != "map" or not set(MATRIX_REQUIRED) <= keys <= set(MATRIX_VALUE_RE):
            rep.bad(f"release.yml release matrix entry {n + 1}: keys {sorted(keys)}; the allowed keys are "
                    f"{list(MATRIX_REQUIRED)} plus optionally `nfpm_arch`" + pin_hint("MATRIX_REQUIRED"))
        for key in sorted(keys):
            val = entry.get(key)
            rx = MATRIX_VALUE_RE.get(key)
            if rx is not None and (val is None or val.style != "plain" or not rx.fullmatch(val.text())):
                rep.bad(f"release.yml release matrix entry {n + 1}: `{key}:` must be an unquoted literal matching "
                        f"`{rx.pattern}` (it is substituted into the pinned build and assert text before bash runs: "
                        "no expression, quote, space or shell metacharacter)" + pin_hint("MATRIX_VALUE_RE"))
        tv = entry.get("target")
        targets.append(tv.text() if tv is not None else "")
    if sorted(targets) != sorted(RELEASE_TARGETS):
        rep.bad(f"release.yml release matrix targets {sorted(targets)} differ from the pinned set "
                f"{sorted(RELEASE_TARGETS)}" + pin_hint("RELEASE_TARGETS"))


def check_release_job(job: Node, rep: Report) -> None:
    if set(job.keys()) != set(JOB_KEYS):
        rep.bad(f"release.yml release job keys {job.keys()} differ from the pinned skeleton {list(JOB_KEYS)} (a job "
                "`if:`, `env:`, `defaults:`, `container:` or `continue-on-error:` can skip or neutralise the assert)"
                + pin_hint("JOB_KEYS"))
    ro = job.get("runs-on")
    if ro is None or ro.style != "plain" or ro.text() != RELEASE_RUNS_ON:
        rep.bad(f"release.yml release job `runs-on:` must be exactly `{RELEASE_RUNS_ON}`" + pin_hint("RELEASE_RUNS_ON"))
    check_matrix(job, rep)
    steps = job_steps(job, "release.yml release job", rep)
    builds = one_unit(steps, KEYS_SHELL, WF_BUILD, "release.yml: the release job build", rep, "WF_BUILD")
    asserts = one_unit(steps, KEYS_SHELL, WF_ASSERT, "release.yml: the release job strict assert", rep, "WF_ASSERT")
    if builds and asserts and min(asserts) < max(builds):
        rep.bad("release.yml: the strict assert must run after the build, in the same job")
    for i, st in steps:
        if i in builds:
            continue
        hit = next((m for m in (BUILD_TOOL_RE.search(unquoted(t)) for t in node_texts(st)) if m), None)
        if hit is not None:
            rep.bad(f"release.yml: release job {step_label(i, st)} runs `{hit.group(0)}`; only the canonical build "
                    "step may run a build tool in the release job (any option order or +toolchain)")


def check_sbom_job(job: Node, rep: Report) -> None:
    if set(job.keys()) != set(SBOM_JOB_KEYS):
        rep.bad(f"release.yml sbom job keys {job.keys()} differ from the pinned skeleton {list(SBOM_JOB_KEYS)}"
                + pin_hint("SBOM_JOB_KEYS"))
    one_unit(job_steps(job, "release.yml sbom job", rep), KEYS_PLAIN, WF_SBOM, "release.yml: the `sbom:` job SBOM", rep, "WF_SBOM")


def pin_problem(node: Optional[Node], spec: Spec, path: str) -> str:
    """Why ``node`` is not exactly the pinned ``spec`` ("" when it is). A mapping
    must have exactly the pinned keys, a sequence exactly the pinned items."""
    if node is None:
        return f"`{path}` is missing"
    if isinstance(spec, dict):
        if node.kind != "map":
            return f"`{path}` must be a mapping (got {node.kind})"
        if set(node.keys()) != set(spec):
            extra, lost = sorted(set(node.keys()) - set(spec)), sorted(set(spec) - set(node.keys()))
            return f"`{path}` keys differ from the pinned set (extra {extra}, missing {lost})"
        for key, sub in spec.items():
            why = pin_problem(node.get(key), sub, f"{path}.{key}")
            if why:
                return why
        return ""
    if isinstance(spec, list):
        items = node.value if node.kind == "seq" and isinstance(node.value, list) else None
        if items is None or len(items) != len(spec):
            return f"`{path}` must be a sequence of exactly {len(spec)} items (got {node.kind}" + (
                f" of {len(items)})" if items is not None else ")")
        for n, (item, sub) in enumerate(zip(items, spec)):
            why = pin_problem(item, sub, f"{path}.{n + 1}")
            if why:
                return why
        return ""
    if spec is None:
        return "" if node.kind == "null" else f"`{path}` must have no value (got {node.kind})"
    if isinstance(spec, Block):
        if node.kind == "block" and node.style == "|" and tuple(node.value) == tuple(spec):  # type: ignore[arg-type]
            return ""
        return f"`{path}` must be exactly the `|` block {list(spec)}"
    style = "flow" if isinstance(spec, Flow) else "double" if isinstance(spec, Double) else "plain"
    if node.kind == "scalar" and node.style == style and node.text() == spec:
        return ""
    got = node.text() if node.kind == "scalar" else ""
    return f"`{path}` must be exactly the {style} value `{spec}` (got {node.kind} {node.style or ''} `{got[:60]}`)"


def pin_hint(const: str) -> str:
    """The actionable tail of every pin-mismatch message."""
    return f"; if this change is intended, update {const} in {GUARD_PATH} in the same commit"


def pin_message(label: str, why: str, const: str) -> str:
    return f"{label}: {why}{pin_hint(const)}"


def docker_step_message(step: Node, spec: Spec, n: int) -> str:
    """The one message for docker job step ``n`` ("" when it is the pinned step).
    A changed SHA of a pinned action (a Dependabot bump) names its constant; the
    rest of the step is then compared as if the new SHA were pinned."""
    at = f"jobs.docker.steps.{n + 1}"
    role = f"release.yml ({DOCKER_STEP_ROLES[n]} step)"
    uses = step.get("uses") if step.kind == "map" else None
    want = spec.get("uses") if isinstance(spec, dict) else None
    if (isinstance(want, str) and uses is not None and uses.kind == "scalar" and uses.style == "plain"
            and uses.text() != want and uses.text().split("@")[0] == want.split("@")[0]):
        const = USES_CONSTANTS[want]
        rest = dict(spec)  # type: ignore[arg-type]
        rest["uses"] = uses.text()
        why = pin_problem(step, rest, at)
        return (f"{role}: `{at}.uses` is `{uses.text()}` but {const} pins `{want}` (an action SHA bump, e.g. "
                f"Dependabot): update {const} in {GUARD_PATH} to the new SHA in the same commit"
                + (f"; also {why}" if why else ""))
    why = pin_problem(step, spec, at)
    return pin_message(role, why, "DOCKER_STEPS") if why else ""


def check_docker_job(jobs: Node, rep: Report) -> None:
    """The docker job holds `packages: write`, so it is pinned WHOLE: its keys and
    values (DOCKER_JOB) and its exact ordered steps (DOCKER_STEPS: keys, SHA-pinned
    `uses`, `with:` inputs, run text). No `env:`, `container:`, `defaults:`,
    `services:`, `strategy:` or extra step can be added."""
    job = jobs.get("docker")
    if job is None or job.kind != "map":
        rep.bad("release.yml: the `docker:` job is missing or not a mapping (the GHCR image is built and pushed only by "
                "the pinned `docker:` job)")
        return
    want_keys = set(DOCKER_JOB) | {"steps"}
    if set(job.keys()) != want_keys:
        extra, lost = sorted(set(job.keys()) - want_keys), sorted(want_keys - set(job.keys()))
        rep.bad(pin_message("release.yml", f"`jobs.docker` keys differ from the pinned set (extra {extra}, missing "
                            f"{lost}; a job `env:`, `container:`, `defaults:`, `services:` or `strategy:` changes what is "
                            "built or pushed)", "DOCKER_JOB"))
    for key, spec in DOCKER_JOB.items():
        why = pin_problem(job.get(key), spec, f"jobs.docker.{key}")
        if why:
            rep.bad(pin_message("release.yml", why, "DOCKER_JOB"))
    steps = job.get("steps")
    items = steps.value if steps is not None and steps.kind == "seq" and isinstance(steps.value, list) else None
    if items is None:
        rep.bad(pin_message("release.yml", "`jobs.docker.steps` must be a sequence", "DOCKER_STEPS"))
        return
    if len(items) != len(DOCKER_STEPS):
        first = next((n for n in range(max(len(items), len(DOCKER_STEPS)))
                      if n >= len(items) or n >= len(DOCKER_STEPS) or docker_step_message(items[n], DOCKER_STEPS[n], n)),
                     0)
        rep.bad(pin_message("release.yml", f"the docker job has {len(items)} steps, the pinned list has "
                            f"{len(DOCKER_STEPS)} (an extra step can build or push an image the guard never read); the "
                            f"first difference is step {first + 1}", "DOCKER_STEPS"))
        return
    for n, (step, spec) in enumerate(zip(items, DOCKER_STEPS)):
        msg = docker_step_message(step, spec, n)
        if msg:
            rep.bad(msg)


def check_release_permissions(doc: Node, jobs: Node, rep: Report) -> None:
    """The job set and every job's `permissions:` are pinned; `packages: write`
    is the docker job's alone (#4719 SR-8)."""
    why = pin_problem(doc.get("permissions"), RELEASE_TOP_PERMISSIONS, "permissions")
    if why:
        rep.bad(pin_message("release.yml", why + " (`packages: write` belongs to the docker job only)",
                            "RELEASE_TOP_PERMISSIONS"))
    if set(jobs.keys()) != set(RELEASE_JOBS):
        extra, lost = sorted(set(jobs.keys()) - set(RELEASE_JOBS)), sorted(set(RELEASE_JOBS) - set(jobs.keys()))
        rep.bad(pin_message("release.yml", f"the job set differs from the pinned one (extra {extra}, missing {lost})",
                            "RELEASE_JOB_PERMISSIONS"))
    for name, want in RELEASE_JOB_PERMISSIONS.items():
        job = jobs.get(name)
        if job is None or job.kind != "map":
            continue
        if job.get("uses") is not None:
            rep.bad(f"release.yml: `jobs.{name}` calls a reusable workflow (`uses:`), which the guard cannot read")
        perms = job.get("permissions")
        if want is None:
            if perms is not None:
                rep.bad(pin_message("release.yml", f"`jobs.{name}.permissions` is declared; the pinned job inherits the "
                                    "top-level `contents: write` and declares none", "RELEASE_JOB_PERMISSIONS"))
            continue
        if name == "docker":
            # #4941 F1: the docker job's permissions are DOCKER_JOB's (RELEASE_JOB_PERMISSIONS["docker"]
            # is derived from it) and check_docker_job pins them: one drift, one message.
            continue
        why = pin_problem(perms, want, f"jobs.{name}.permissions")
        if why:
            rep.bad(pin_message("release.yml", why, "RELEASE_JOB_PERMISSIONS"))


def node_lines(node: Node) -> Iterator[Tuple[int, str]]:
    """(0-based line, text) of a scalar, or of each line of a block scalar."""
    if node.kind == "scalar":
        yield node.line, node.text()
    elif node.kind == "block" and isinstance(node.value, list):
        for k, line in enumerate(node.value):
            yield node.line + 1 + k, line


def check_secrets_and_registry(doc: Node, rep: Report) -> None:
    """Every `secrets` reference is `secrets.<NAME>` with NAME in RELEASE_SECRETS,
    no key is named `secrets`, and the image registry is named only inside the
    pinned docker job."""
    for path, node in walk(doc):
        if path and path[-1].lower() == "secrets":
            rep.bad(f"release.yml: `{'.'.join(path)}` passes secrets on (a `secrets:` key is refused)")
        in_docker = path[:2] == ("jobs", "docker")
        for line, text in node_lines(node):
            for m in SECRET_REF_RE.finditer(text):
                if m.group("name") not in RELEASE_SECRETS or m.group(0) != "secrets." + str(m.group("name")):
                    rep.bad(pin_message("release.yml", f"line {line + 1}: `{m.group(0)[:40]}` is not `secrets.<NAME>` "
                                        "with a pinned NAME (a new credential is refused until it is pinned)",
                                        "RELEASE_SECRETS"))
            if not in_docker and REGISTRY in text.lower():
                rep.bad(f"release.yml: line {line + 1}: `{REGISTRY}` outside the pinned `docker:` job (only that job may "
                        f"address the image registry): {text.strip()[:70]}")


def check_run_continuations(doc: Node, label: str, rep: Report) -> None:
    """No run text line may end in a backslash: every pinned unit is compared statement by
    statement, and a joined line is a second spelling the guard refuses to model."""
    for path, node in walk(doc):
        if not path or path[-1] != "run":
            continue
        for line, text in node_lines(node):
            if text.rstrip(" \t").endswith("\\"):
                rep.bad(f"{label}: line {line + 1}: a run line ends in `\\` (a line continuation; join the line, the "
                        f"guard refuses continuations in run text): {text.strip()[:70]}")


def check_release_yml(text: str, rep: Report) -> None:
    check_no_bash_env("release.yml", text, rep)
    check_text_counts(text, rep)
    doc = parse_yaml(text, "release.yml", rep)
    if doc is None:
        return
    check_blocks(doc, "release.yml", rep)
    check_run_continuations(doc, "release.yml", rep)
    check_secrets_and_registry(doc, rep)
    for key in doc.keys():
        if key not in TOP_KEYS:
            rep.bad(f"release.yml top level: `{key}:` is not allowed (allowed: {', '.join(TOP_KEYS)})" + pin_hint("TOP_KEYS"))
    jobs = doc.get("jobs")
    if not want_kind(jobs, "map", "release.yml `jobs:`", rep) or jobs is None:
        return
    check_release_permissions(doc, jobs, rep)
    release, sbom = jobs.get("release"), jobs.get("sbom")
    if want_kind(release, "map", "release.yml `jobs.release`", rep) and release is not None:
        check_release_job(release, rep)
    if want_kind(sbom, "map", "release.yml `jobs.sbom`", rep) and sbom is not None:
        check_sbom_job(sbom, rep)
    check_docker_job(jobs, rep)


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
                f"parses the file): {raw[0][:60]}" + pin_hint("DOCKER_SYNTAX"))
    for n, ln in enumerate(raw[1:], 2):
        if DIRECTIVE_RE.match(ln):
            rep.bad(f"Dockerfile: line {n}: a parser directive other than the pinned line-1 syntax (an `escape` "
                    f"directive changes what a line continuation is): {ln.strip()[:60]}")
    stages: List[Tuple[Optional[str], List[str]]] = []
    names: Dict[str, int] = {}
    spans = bk_instructions(raw)
    canon_lines: set = set()
    for first, last, ins in spans:
        if ins == DOCKER_RUN:
            if tuple(raw[first - 1:last]) == DOCKER_RUN_LINES:
                canon_lines.update(range(first, last + 1))
            else:
                # #4946: the RUN is the canonical instruction written differently (a trailing
                # space after a backslash, a re-indent): its own lines are not stray continuations.
                canon_lines.update(set(range(first, last + 1)))
                rep.bad(pin_message("Dockerfile", f"line {first}: the build RUN is not written exactly as the pinned "
                                    "physical lines (compared line by line, no comment or blank line inside)",
                                    "DOCKER_RUN_LINES"))
    for n in continued_lines(raw):
        if n not in canon_lines:
            rep.bad(f"Dockerfile: line {n}: a line ending in `\\` outside the canonical build RUN (DOCKER_RUN_LINES in "
                    f"{GUARD_PATH}); continuations are refused everywhere else: {raw[n - 1].strip()[:60]}")
    for _, _, ins in spans:
        word = ins.split(" ", 1)[0].upper()
        if "--mount" in ins.lower():
            rep.bad(f"Dockerfile: `--mount` refused (a mount can overlay or import files the guard never read): {ins[:60]}")
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
            if "$" in image:
                rep.bad(f"Dockerfile: FROM image `{image}` is a variable; a stage must start FROM a literal base image "
                        f"(the guard cannot resolve it): {ins[:60]}")
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
            if BUILD_TOOL_RE.search(unquoted(ins)) and not canon:
                rep.bad(f"Dockerfile: a build tool outside the canonical build RUN (the last instruction of the stage the "
                        f"image copies the binary from): {ins[:80]}")
    builder = stages[bidx][1]
    for ins in builder:
        if FROM_FLAG_RE.search(ins):
            rep.bad(f"Dockerfile: the builder stage takes `--from` another stage or image: {ins[:60]}")
    if DOCKER_LOCK_COPY not in builder[:-2]:
        rep.bad(f"Dockerfile: the builder stage does not `{DOCKER_LOCK_COPY}` before the build" + pin_hint("DOCKER_LOCK_COPY"))
    if builder[-2:-1] != [DOCKER_DECL_COPY]:
        rep.bad(f"Dockerfile: the builder stage must `{DOCKER_DECL_COPY}` immediately before the build RUN"
                + pin_hint("DOCKER_DECL_COPY"))
    if builder[-1:] != [DOCKER_RUN]:
        rep.bad("Dockerfile: the builder stage must END with exactly the allowed build+assert RUN (nothing after it); "
                + docker_nearest(builder) + pin_hint("DOCKER_RUN"))


def check_inline_use(name: str, text: str, rep: Report) -> None:
    """Every use of the declaration is its own assignment (a failing declaration
    inside a substitution in another command would be swallowed)."""
    for ln in logical_lines(text.split("\n")):
        stripped = ln.replace(ALLOWED_FEATURES, "").replace(ALLOWED_REQUIRE, "")
        if INLINE_USE_RE.search(stripped):
            rep.bad(f"{name}: inline use of the declaration (a failure would be swallowed; assign it in its own statement): {ln[:80]}")


def _shape_norm(lines: Tuple[str, ...]) -> Tuple[str, ...]:
    """The proof statements with the TLS URL assignment (any port) replaced by its placeholder."""
    if len(lines) == len(SHAPE_PROOF) and SHAPE_URL_RE.fullmatch(lines[1]):
        return (lines[0], SHAPE_PROOF_URL, lines[2])
    return lines


def check_shape(text: str, rep: Report, advisory: Optional[bool] = None) -> None:
    """release-shape.yml is pinned as a skeleton (#4719 SR-10): top-level keys,
    `on:`, `permissions:` and `env:` values, the one job's keys and values, and
    the build and proof units inside it. ``advisory`` defaults to SHAPE_ADVISORY."""
    if advisory is None:
        advisory = SHAPE_ADVISORY
    check_no_bash_env("release-shape.yml", text, rep)
    doc = parse_yaml(text, "release-shape.yml", rep)
    if doc is None:
        return
    check_blocks(doc, "release-shape.yml", rep)
    check_run_continuations(doc, "release-shape.yml", rep)
    if doc.keys() != list(SHAPE_TOP_KEYS):
        rep.bad(pin_message("release-shape.yml", f"top-level keys {doc.keys()} differ from the pinned "
                            f"{list(SHAPE_TOP_KEYS)} (a top-level `defaults:` or `env:` change redirects every step)",
                            "SHAPE_TOP_KEYS"))
    for key, spec, const in (("on", SHAPE_ON, "SHAPE_ON"), ("permissions", SHAPE_PERMISSIONS, "SHAPE_PERMISSIONS"),
                             ("env", SHAPE_ENV, "SHAPE_ENV")):
        why = pin_problem(doc.get(key), spec, key)
        if why:
            rep.bad(pin_message("release-shape.yml", why, const))
    jobs = doc.get("jobs")
    if jobs is None or jobs.kind != "map" or jobs.keys() != ["release-shape"]:
        rep.bad("release-shape.yml: `jobs:` must be exactly the one `release-shape:` job" + pin_hint("SHAPE_JOB"))
    job = jobs.get("release-shape") if jobs is not None else None
    if not want_kind(job, "map", "release-shape.yml `jobs.release-shape`", rep) or job is None:
        return
    want_keys = set(SHAPE_JOB) | {"steps"}
    if set(job.keys()) - {"continue-on-error"} != want_keys:
        extra = sorted(set(job.keys()) - want_keys - {"continue-on-error"})
        rep.bad(pin_message("release-shape.yml", f"`jobs.release-shape` keys {job.keys()} differ from the pinned set "
                            f"(extra {extra}, missing {sorted(want_keys - set(job.keys()))}; `needs:`, `if:`, `env:`, "
                            "`defaults:`, `container:` or `services:` can skip or redirect the proof)", "SHAPE_JOB"))
    for key, spec in SHAPE_JOB.items():
        why = pin_problem(job.get(key), spec, f"jobs.release-shape.{key}")
        if why:
            rep.bad(pin_message("release-shape.yml", why, "SHAPE_JOB"))
    coe = job.get("continue-on-error")
    if advisory:
        why = pin_problem(coe, "true", "jobs.release-shape.continue-on-error")
        if why:
            rep.bad(f"release-shape.yml: {why}; while SHAPE_ADVISORY is True in {GUARD_PATH} (#4480) the job carries "
                    "exactly the plain `continue-on-error: true`")
    elif coe is not None:
        rep.bad(f"release-shape.yml: `jobs.release-shape.continue-on-error` is set but SHAPE_ADVISORY is False in "
                f"{GUARD_PATH} (#4720: the job is required, a failing proof must fail the run)")
    steps = job_steps(job, "release-shape.yml release-shape job", rep)
    builds = one_unit(steps, KEYS_SHELL, SHAPE_BUILD, "release-shape.yml: the `release-shape:` job build", rep,
                      "SHAPE_BUILD")
    proofs = one_unit(steps, KEYS_SHELL, SHAPE_PROOF, "release-shape.yml: the `release-shape:` job pg proof "
                      "(an executing `bash scripts/release-shape-pg-proof.sh` run step; the `paths:` filter does not count)",
                      rep, "SHAPE_PROOF", _shape_norm)
    if builds and proofs and proofs[0] < builds[0]:
        rep.bad("release-shape.yml: the pg proof must run after the release-shaped build, in the same job")


def check_install(text: str, rep: Report) -> None:
    m = re.search(r"^## Pre-built Binaries.*?(?=^## (?!Pre-built Binaries))", text, re.M | re.S)
    section = m.group(0) if m else ""
    if "sal-postgres" not in section:
        rep.bad("docs/INSTALL.md 'Pre-built Binaries' does not name sal-postgres")
    if "daemon path is NOT" in section or "requires a `--features sal,sal-postgres` source build" in section:
        rep.bad("docs/INSTALL.md still says the postgres path needs a source build")


def run_guard(root: Path, advisory: Optional[bool] = None) -> Tuple[List[str], str]:
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
        check_shape(shape, rep, advisory)
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
SHAPE_JOB_HDR = "\n  release-shape:\n"


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


BUILD_IMG_NAME = "      - name: Build and push Docker image\n"
ATTEST_NAME = "      - name: Attest build provenance (Docker image)\n"
PUSH_USES = "        uses: " + IMAGE_BUILD_USES + " # v6\n"
BUILDX_STEP = "      - name: Set up Docker Buildx\n        uses: " + BUILDX_USES + " # v3\n"
LOGIN_NAME = "      - name: Log in to GitHub Container Registry\n"
PUSH_CACHE = "          cache-from: type=gha\n          cache-to: type=gha,mode=max\n"
PUSH_TAGS = "          tags: |\n"
PUSH_LABELS = "          labels: |\n"
SHAPE_PROOF_LINE = "          " + SHAPE_PROOF_CMD
PROOF_NAME = "      - name: Prove the shipped binary reports sal-postgres and uses the tier over verify-full\n"
SHAPE_BUILD_NAME = "      - name: Build release binary (exactly as release.yml)\n"


def _image_step(text: str) -> str:
    a = text.index(BUILD_IMG_NAME)
    return text[a:text.index(ATTEST_NAME, a)]


def _drop_image_with(text: str) -> str:
    step = _image_step(text)
    return text.replace(step, step[: step.index(PUSH_WITH)], 1)


def _image_with_scalar(text: str) -> str:
    step = _image_step(text)
    return text.replace(step, step[: step.index(PUSH_WITH)] + "        with: none\n", 1)


def _second_image_build(text: str) -> str:
    step = _image_step(text)
    return text.replace(step, step + step, 1)


def _image_build_in_sbom_job(text: str) -> str:
    step = _image_step(text)
    return text.replace(step, "", 1).replace(SBOM_HDR, step + SBOM_HDR, 1)


def _image_build_copy_in_sbom_job(text: str) -> str:
    return text.replace(SBOM_HDR, _image_step(text) + SBOM_HDR, 1)


def _swap_cache_order(text: str) -> str:
    return text.replace(PUSH_CACHE, "          cache-to: type=gha,mode=max\n          cache-from: type=gha\n", 1)


def _reusable_builder_job(text: str) -> str:
    return text.rstrip("\n") + "\n\n  builder:\n    uses: docker/build-push-action/.github/workflows/x.yml@v6\n"


def _proof_before_build(text: str) -> str:
    b = text.index(PROOF_NAME)
    step = text[b:text.index("      - name: Stop the PostgreSQL service", b)]
    return text.replace(step, "", 1).replace(SHAPE_BUILD_NAME, step + SHAPE_BUILD_NAME, 1)


def _drop_proof_step(text: str) -> str:
    b = text.index(PROOF_NAME)
    return text.replace(text[b:text.index("      - name: Stop the PostgreSQL service", b)], "", 1)


def _d(old: str, new: str) -> Edit:
    return _docker(old, new)


DOCKER_HDR = "\n  docker:\n    name: Docker (GHCR)\n"
DOCKER_HEAD = ("needs: [preflight, qualify, supply-chain]\n    if: needs.preflight.outputs.is_prerelease == 'false'\n"
               "    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n      packages: write\n")
CRATES_STEPS = ("    # CARGO_REGISTRY_TOKEN is scoped to the `release` Environment (#3546 D4).\n"
                "    environment: release\n    steps:\n")
COPR_HDR = "  copr:\n    name: Fedora COPR\n"
LOGIN_PW = "          password: ${{ secrets.GITHUB_TOKEN }}\n"
SHAPE_NAME = '    name: "Release-shaped build + PG TLS proof"\n'
REL_PERMS = "      id-token: write\n      attestations: write\n    strategy:\n"


def _docker_extra_step(body: str) -> List[Edit]:
    """A new docker-job step before the image build."""
    return [_rel(BUILD_IMG_NAME, "      - name: extra\n" + body + BUILD_IMG_NAME)]


def _docker_step_last(text: str) -> str:
    """An extra docker-job step after the provenance attestation (the last pinned step)."""
    c = text.index("\n  copr:\n")
    return text[:c].rstrip("\n") + "\n      - name: extra\n        run: echo done\n\n" + text[c:]


def _docker_job_scalar(text: str) -> str:
    a, c = text.index("\n  docker:\n"), text.index("\n  copr:\n")
    return text[:a] + "\n  docker: none\n" + text[c:]


def _docker_steps_scalar(text: str) -> str:
    a, c = text.index("\n  docker:\n"), text.index("\n  copr:\n")
    s = text.index("    steps:\n", a)
    return text[:s] + "    steps: none\n" + text[c:]


def _shape(old: str, new: Union[str, Transform]) -> Edit:
    return (SHAPE, old, new, False)


# name -> (want, edits). want: "pass" (guard accepts), "fail" (guard refuses),
# "input-error" (guard exits 2). `--mutation-sweep` neutralises every refusal
# site in turn and requires `--self-test` to go red, so each "fail" case must be
# refused by a distinct refusal, not merely by a neighbour.
CASES: Dict[str, Tuple[str, List[Edit]]] = {
    "unmutated": ("pass", []),
    "C1 multi-line build (a run continuation) is refused": ("fail", [_rel(
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
    "release-shape build job renamed": ("fail", [(SHAPE, SHAPE_JOB_HDR, "\n  release-shape-x:\n", False)]),
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
    # --- #4719 review round 2 (F1/SR-4): the image build is an allowlist
    "IB file: on the image build": ("fail", [_rel(PUSH_WITH, PUSH_WITH + "          file: Dockerfile.alt\n")]),
    "IB context other than the repository root": ("fail", [_rel(PUSH_WITH, PUSH_WITH.replace("context: .", "context: ./deploy"))]),
    "IB with: is a scalar": ("fail", [_rel(BUILD_IMG_NAME, _image_with_scalar)]),
    "IB context missing": ("fail", [_rel(PUSH_WITH, "        with:\n")]),
    "IB with: missing": ("fail", [_rel(BUILD_IMG_NAME, _drop_image_with)]),
    "IB build-contexts replaces the builder stage": ("fail", [_rel(
        PUSH_WITH, PUSH_WITH + "          build-contexts: builder=docker-image://alpine\n")]),
    "IB build-args overrides the frontend": ("fail", [_rel(
        PUSH_WITH, PUSH_WITH + "          build-args: BUILDKIT_SYNTAX=ghcr.io/x/frontend\n")]),
    "IB platforms added": ("fail", [_rel(PUSH_WITH, PUSH_WITH + "          platforms: linux/riscv64\n")]),
    "IB owner/action in another case": ("fail", [_rel(PUSH_USES, PUSH_USES.replace("docker/build-push", "Docker/Build-Push"))]),
    "IB uses spelled with a YAML escape": ("fail", [_rel(
        PUSH_USES, '        uses: "\\x64ocker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8"\n')]),
    "IB uses double-quoted (no escape)": ("fail", [_rel(PUSH_USES, PUSH_USES.replace(IMAGE_BUILD_USES, '"' + IMAGE_BUILD_USES + '"'))]),
    "IB uses single-quoted": ("fail", [_rel(PUSH_USES, PUSH_USES.replace(IMAGE_BUILD_USES, "'" + IMAGE_BUILD_USES + "'"))]),
    "IB uses pinned to another commit": ("fail", [_rel(PUSH_USES, PUSH_USES.replace("10e90e36", "00000000"))]),
    "IB uses swapped for another image builder": ("fail", [_rel(PUSH_USES, "        uses: int128/kaniko-action@v1\n")]),
    "IB step id changed": ("fail", [_rel("        id: build\n", "        id: image\n")]),
    "IB step carries env": ("fail", [_rel(PUSH_USES, PUSH_USES + "        env:\n          DOCKER_BUILDKIT: '0'\n")]),
    "IB step carries if": ("fail", [_rel(PUSH_USES, PUSH_USES + "        if: false\n")]),
    "IB step name carries an expression": ("fail", [_rel(BUILD_IMG_NAME, "      - name: Build ${{ github.actor }}\n")]),
    "IB push value changed": ("fail", [_rel("push: ${{ github.event.inputs.dry_run == 'false' }}", "push: true")]),
    "IB push value quoted": ("fail", [_rel("push: ${{ github.event.inputs.dry_run == 'false' }}",
                                          "push: '${{ github.event.inputs.dry_run == ''false'' }}'")]),
    "IB tags changed": ("fail", [_rel(PUSH_TAGS, PUSH_TAGS + "            ghcr.io/other/ai-memory:latest\n")]),
    "IB labels changed": ("fail", [_rel(PUSH_LABELS, PUSH_LABELS + "            extra=1\n")]),
    "IB cache-from changed": ("fail", [_rel("cache-from: type=gha", "cache-from: type=registry,ref=x/y")]),
    "IB cache-to changed": ("fail", [_rel("cache-to: type=gha,mode=max", "cache-to: type=gha")]),
    "IB second image build in the docker job": ("fail", [_rel(BUILD_IMG_NAME, _second_image_build)]),
    "IB image build moved to the sbom job": ("fail", [_rel(BUILD_IMG_NAME, _image_build_in_sbom_job)]),
    "IB image build copied into the sbom job": ("fail", [_rel(BUILD_IMG_NAME, _image_build_copy_in_sbom_job)]),
    "IB image build step deleted": ("fail", [_rel(BUILD_IMG_NAME, lambda t: t.replace(_image_step(t), "", 1))]),
    "IB docker build in a docker-job run step": ("fail", _docker_extra_step("        run: docker build -t x .\n")),
    "IB docker buildx build in a docker-job run step": ("fail", _docker_extra_step("        run: |\n          docker  buildx build --push .\n")),
    "IB quoted docker build in a docker-job run step": ("fail", _docker_extra_step("        run: d''ocker build .\n")),
    "IB buildctl in a docker-job run step": ("fail", _docker_extra_step("        run: buildctl build --frontend dockerfile.v0\n")),
    "IB reusable image-build workflow job": ("fail", [_rel(BUILD_IMG_NAME, _reusable_builder_job)]),
    "IB buildx setup carries with": ("fail", [_rel(BUILDX_STEP, BUILDX_STEP + "        with:\n          driver-opts: image=x\n")]),
    "IB buildx setup in another case": ("fail", [_rel(BUILDX_STEP, BUILDX_STEP.replace("docker/setup", "Docker/setup"))]),
    "IB login carries another key": ("fail", [_rel(LOGIN_NAME, LOGIN_NAME + "        env:\n          X: y\n")]),
    "valid: image build with: keys reordered": ("pass", [_rel(PUSH_CACHE, _swap_cache_order)]),
    # --- #4719 review round 2 (SR-5/F1): double-quoted escapes are never decoded
    "SR5/S10 double-quoted run spells cargo with an escape": ("fail", _step_before_pkg(
        '        run: "\\x63argo build --release --target ${{ matrix.target }}"\n')),
    "SR5/S13 double-quoted second SBOM spelled with an escape": ("fail", [_rel(
        SBOM_HDR, '      - name: x\n        run: "\\x63argo cyclonedx --format json"\n' + SBOM_HDR)]),
    "SR5/S14 pinned step name spelled with an escape": ("fail", [_rel(ASSERT_NAME, '      - name: "\\x24{{ github.actor }}"\n')]),
    "SR5 backslash in any double-quoted scalar": ("fail", [_rel(JOB_NAME, '    name: "Release\\tx"\n')]),
    "SR5 valid double-quoted scalar without a backslash": ("pass", [_rel(PKG_HDR, '      - name: "Package binary"\n')]),
    # --- #4719 SR-7: quote characters inside a command word
    "SR7/S12 plain c''argo build in a later release step": ("fail", _step_before_pkg("        run: c''argo build --release\n")),
    "SR7 c\"\"argo build in a later release step": ("fail", _step_before_pkg('        run: c""argo build --release\n')),
    "SR7 ca\\rgo build in a later release step": ("fail", _step_before_pkg("        run: ca\\rgo build --release\n")),
    "SR7 c'a'rgo build in a block run": ("fail", _step_before_pkg("        run: |\n          c'a'rgo build --release\n")),
    "SR7 second matrix-target build spelled c''argo in another job": ("fail", [_rel(
        SBOM_HDR, "      - name: x\n        run: c''argo build --target ${{ matrix.target }}\n" + SBOM_HDR)]),
    "SR7 second SBOM spelled c''argo": ("fail", [_rel(
        SBOM_HDR, "      - name: x\n        run: c''argo cyclonedx --format json\n" + SBOM_HDR)]),
    # --- #4719 F3: YAML subset keys
    "F3 space before the colon on runs-on": ("fail", [_rel(NEEDS_REL, NEEDS_REL.replace("runs-on:", "runs-on :"))]),
    "F3 space before the colon on a step key": ("fail", _hdr_key(ASSERT_NAME, "if : false")),
    "F3 space before the colon on the job key": ("fail", [_rel("\n  release:\n", "\n  release :\n")]),
    # --- #4719 F2/F3/F4: Dockerfile parity with BuildKit
    "D11 blank line inside a continuation swallows the binary COPY": ("fail", [_docker(D_BIN, "VOLUME /data \\\n\n" + D_BIN)]),
    "D12 comment line inside the build RUN continuation": ("fail", [_docker(
        '    strip target/release/ai-memory; \\', '    # note\n    strip target/release/ai-memory; \\')]),
    "D12b comment line inside another instruction's continuation": ("fail", [_docker(D_BIN, "LABEL a=1 \\\n# c\n b=2\n" + D_BIN)]),
    "D13 final stage FROM a variable": ("fail", [_docker(D_FINAL, "FROM ${BASE}\n")]),
    "D13b builder stage FROM a variable": ("fail", [_docker(D_BUILDER, "FROM ${BASE} AS builder\n")]),
    "D15 lowercase instruction in the final stage": ("pass", [_docker(D_BIN, D_BIN + "label org.example.x=1\n")]),
    "D15b mixed-case binary COPY is not the binary COPY": ("fail", [_docker(D_BIN, D_BIN.replace("COPY", "Copy"))]),
    "D16 RUN --mount from= in the builder": ("fail", [_docker(D_LOCK, D_LOCK + "RUN --mount=type=bind,from=busybox,target=/m true\n")]),
    "D16b RUN --mount in the final stage": ("fail", [_docker(D_BIN, D_BIN + "RUN --mount=type=bind,from=busybox,target=/m true\n")]),
    "D16c lowercase run --mount": ("fail", [_docker(D_BIN, D_BIN + "run --mount=type=cache,target=/m true\n")]),
    # --- #4719 SR-6/P4/P5/P6: the pg proof is a real, executing, fatal run step
    "P4 the only proof invocation replaced by true": ("fail", [(SHAPE, SHAPE_PROOF_CMD, "true", False)]),
    "P6 continue-on-error on the proof step": ("fail", [(SHAPE, PROOF_NAME, PROOF_NAME + "        continue-on-error: true\n", False)]),
    "P5 if: false on the proof step": ("fail", [(SHAPE, PROOF_NAME, PROOF_NAME + "        if: false\n", False)]),
    "P5b if on the release-shape job": ("fail", [(SHAPE, "    runs-on: ubuntu-latest\n    # Advisory", "    runs-on: ubuntu-latest\n    if: false\n    # Advisory", False)]),
    "P7 proof step deleted": ("fail", [(SHAPE, PROOF_NAME, _drop_proof_step, False)]),
    "P8 proof runs before the build": ("fail", [(SHAPE, PROOF_NAME, _proof_before_build, False)]),
    "P9 proof invocation made non-fatal": ("fail", [(SHAPE, SHAPE_PROOF_CMD, SHAPE_PROOF_CMD + " || true", False)]),
    "P10 proof invocation prefixed with a false test": ("fail", [(SHAPE, SHAPE_PROOF_CMD, "false && " + SHAPE_PROOF_CMD, False)]),
    "P11 proof run block gains a statement": ("fail", [(SHAPE, SHAPE_PROOF_LINE, "          exit 0\n" + SHAPE_PROOF_LINE, False)]),
    "P12 proof step carries env": ("fail", [(SHAPE, PROOF_NAME, PROOF_NAME + "        env:\n          X: y\n", False)]),
    "P13 proof invoked with a different binary": ("fail", [(SHAPE, SHAPE_PROOF_CMD, SHAPE_PROOF_CMD.replace("target/release/ai-memory", "/bin/true"), False)]),
    "P14 proof step name carries an expression": ("fail", [(SHAPE, PROOF_NAME, PROOF_NAME.replace("tier", "tier ${{ github.actor }}"), False)]),
    "P15 proof URL points at another host": ("fail", [(SHAPE, "127.0.0.1:55432/proof", "198.51.100.7:55432/proof", False)]),
    "D16d uppercase RUN --MOUNT": ("fail", [_docker(D_BIN, D_BIN + "RUN --MOUNT=type=cache,target=/m true\n")]),
    "valid: proof URL port changed": ("pass", [(SHAPE, "127.0.0.1:55432/proof", "127.0.0.1:55433/proof", False)]),
    # --- #4719 round 5 SR-8: the docker job is pinned whole; no other job may reach the registry
    "SR8/I01 absolute-path docker push in a docker-job step": ("fail", _docker_extra_step("        run: /usr/bin/docker push x\n")),
    "SR8/I02 docker -H push in a docker-job step": ("fail", _docker_extra_step("        run: docker -H tcp://x:2375 push x\n")),
    "SR8/I05 registry copy tool in a docker-job step": ("fail", _docker_extra_step("        run: crane copy a b\n")),
    "SR8/I09 another push action in the docker job": ("fail", _docker_extra_step("        uses: some/push-action@v1\n")),
    "SR8/I10 local composite action in the docker job": ("fail", _docker_extra_step("        uses: ./.github/actions/x\n")),
    "SR8 extra step after the attestation": ("fail", [_rel(BUILD_IMG_NAME, _docker_step_last)]),
    "SR8/I11 registry copy in the crates-io job": ("fail", [_rel(
        CRATES_STEPS, CRATES_STEPS + "      - name: extra\n        run: crane copy x ghcr.io/o/ai-memory:latest\n")]),
    "SR8/I11b upper-case registry name in the crates-io job": ("fail", [_rel(
        CRATES_STEPS, CRATES_STEPS + "      - name: extra\n        run: crane copy x GHCR.IO/o/ai-memory:latest\n")]),
    "SR8 top-level packages write": ("fail", [_rel("\npermissions:\n  contents: write\n",
                                                  "\npermissions:\n  contents: write\n  packages: write\n")]),
    "SR8 crates-io declares permissions": ("fail", [_rel(CRATES_STEPS, CRATES_STEPS.replace(
        "    environment:", "    permissions:\n      packages: write\n    environment:"))]),
    "SR8 release job permissions changed": ("fail", [_rel(REL_PERMS, "      id-token: write\n    strategy:\n")]),
    "SR8 copr job calls a reusable workflow": ("fail", [_rel(COPR_HDR, COPR_HDR + "    uses: ./.github/workflows/x.yml\n")]),
    "SR8 an extra job": ("fail", [_rel(COPR_HDR, _append_job("      - run: echo\n"))]),
    "SR8 unpinned secret": ("fail", _step_before_pkg("        env:\n          T: ${{ secrets.NPM_TOKEN }}\n        run: echo\n")),
    "SR8 secrets dotted with spaces": ("fail", _step_before_pkg("        env:\n          T: ${{ secrets . GITHUB_TOKEN }}\n        run: echo\n")),
    "4942 SECRETS upper-case unpinned name": ("fail", _step_before_pkg(
        "        env:\n          T: ${{ SECRETS.NPM_TOKEN }}\n        run: echo\n")),
    "4942 Secrets mixed-case unpinned name": ("fail", _step_before_pkg(
        "        env:\n          T: ${{ Secrets.NPM_TOKEN }}\n        run: echo\n")),
    "4942 SECRETS upper-case with a pinned name": ("fail", _step_before_pkg(
        "        env:\n          T: ${{ SECRETS.GITHUB_TOKEN }}\n        run: echo\n")),
    "4942 Secrets: mixed-case key passes secrets on": ("fail", [_rel(COPR_HDR, COPR_HDR + "    Secrets: inherit\n")]),
    "4942 valid: secrets only as the tail of another name": ("pass", _step_before_pkg(
        "        run: echo not-secrets.X mysecrets.Y github.secrets.Z\n")),
    "4944 run line ending in a backslash and a space (release.yml)": ("fail", _step_before_pkg(
        "        run: |\n          echo a \\ \n          echo b\n")),
    "SR8 all secrets as JSON": ("fail", _step_before_pkg("        env:\n          T: ${{ toJSON(secrets) }}\n        run: echo\n")),
    "SR8 secrets: inherit": ("fail", [_rel(COPR_HDR, COPR_HDR + "    secrets: inherit\n")]),
    "valid: pinned secret in a release step": ("pass", _step_before_pkg(
        "        env:\n          T: ${{ secrets.GITHUB_TOKEN }}\n        run: echo\n")),
    # --- SR-9: docker job keys and values
    "SR9/D01 docker job env": ("fail", [_rel(DOCKER_HDR, DOCKER_HDR + "    env:\n      DOCKER_HOST: tcp://x:2375\n")]),
    "SR9/D03 docker job container": ("fail", [_rel(DOCKER_HDR, DOCKER_HDR + "    container: alpine\n")]),
    "SR9/D04 docker job runs-on self-hosted": ("fail", [_rel(DOCKER_HEAD, DOCKER_HEAD.replace("ubuntu-latest", "self-hosted"))]),
    "SR9 docker job needs changed": ("fail", [_rel(DOCKER_HEAD, DOCKER_HEAD.replace(", supply-chain]", "]"))]),
    "SR9 docker job if changed": ("fail", [_rel(DOCKER_HEAD, DOCKER_HEAD.replace("== 'false'", "== 'true'"))]),
    "SR9 docker job missing": ("fail", [_rel(DOCKER_HDR, _docker_job_scalar)]),
    "SR9 docker steps not a sequence": ("fail", [_rel(DOCKER_HDR, _docker_steps_scalar)]),
    "X05 docker step id quoted": ("fail", [_rel("        id: build\n", "        id: 'build'\n")]),
    "X09 registry login carries another with key": ("fail", [_rel(LOGIN_PW, LOGIN_PW + "          logout: false\n")]),
    "X04 image tags as a folded block": ("fail", [_rel(PUSH_TAGS, "          tags: >\n")]),
    "IB attestation push-to-registry quoted": ("fail", [_rel("push-to-registry: true", "push-to-registry: 'true'")]),
    # --- SR-10: the release-shape skeleton
    "SR10/P20b needs on the release-shape job": ("fail", [_shape(SHAPE_NAME, SHAPE_NAME + "    needs: [x]\n")]),
    "SR10/P21 job defaults": ("fail", [_shape(SHAPE_NAME, SHAPE_NAME + "    defaults:\n      run:\n        working-directory: x\n")]),
    "SR10/P22 job env": ("fail", [_shape(SHAPE_NAME, SHAPE_NAME + "    env:\n      X: y\n")]),
    "SR10/P22b top-level env BASH_ENV": ("fail", [_shape('  CARGO_INCREMENTAL: "0"\n', '  CARGO_INCREMENTAL: "0"\n  BASH_ENV: x\n')]),
    "SR10 top-level env gains a key": ("fail", [_shape('  CARGO_INCREMENTAL: "0"\n', '  CARGO_INCREMENTAL: "0"\n  X: y\n')]),
    "SR10 CARGO_INCREMENTAL unquoted": ("fail", [_shape('  CARGO_INCREMENTAL: "0"\n', "  CARGO_INCREMENTAL: 0\n")]),
    "SR10/P22c top-level defaults": ("fail", [_shape("\nenv:\n", "\ndefaults:\n  run:\n    working-directory: x\n\nenv:\n")]),
    "SR10/P23 job container": ("fail", [_shape(SHAPE_NAME, SHAPE_NAME + "    container: alpine\n")]),
    "SR10 job name changed": ("fail", [_shape(SHAPE_NAME, '    name: "Release shape"\n')]),
    "SR10 job runs-on changed": ("fail", [_shape("    runs-on: ubuntu-latest\n    # Advisory", "    runs-on: self-hosted\n    # Advisory")]),
    "SR10 job timeout changed": ("fail", [_shape("    timeout-minutes: 60\n", "    timeout-minutes: 600\n")]),
    "SR10 an extra job": ("fail", [_shape(SHAPE_NAME, lambda t: t.rstrip("\n") + "\n\n  other:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n")]),
    "SR10 permissions changed": ("fail", [_shape("permissions:\n  contents: read\n", "permissions:\n  contents: write\n")]),
    "SR10/P25 last path filter dropped": ("fail", [_shape('      - "migrations/**"\n', "")]),
    "4941 SR10 middle path filter changed": ("fail", [_shape('      - "src/**"\n', '      - "docs/**"\n')]),
    "4941 SR10 last path filter changed": ("fail", [_shape('      - "migrations/**"\n', '      - "other/**"\n')]),
    "4941 SR10 later pull_request branch changed": ("fail", [_shape('"rehearsal/**", "main"]', '"rehearsal/**", "mainx"]')]),
    "4943 SR10 BASH_ENV in the env of an unpinned shape step": ("fail", [_shape(
        "        run: python3 scripts/check_release_features.py\n",
        "        run: python3 scripts/check_release_features.py\n        env:\n          BASH_ENV: x\n")]),
    "4943 SR10 BASH_ENV written to GITHUB_ENV by an unpinned shape step": ("fail", [_shape(
        "        run: python3 scripts/check_release_features.py\n",
        "        run: |\n          echo \"BASH_ENV=x\" >> \"$GITHUB_ENV\"\n          python3 scripts/check_release_features.py\n")]),
    "4944 SR10 run line ending in a backslash and a space": ("fail", [_shape(
        "        run: python3 scripts/check_release_features.py\n",
        "        run: |\n          echo a \\ \n          echo b\n")]),
    "4945 SR10 top-level keys reordered": ("fail", [
        _shape("\npermissions:\n  contents: read\n", ""),
        _shape("  cancel-in-progress: true\n", "  cancel-in-progress: true\n\npermissions:\n  contents: read\n")]),
    "SR10 push branches widened": ("fail", [_shape('branches: ["release/**"]\n', 'branches: ["release/**", "x"]\n')]),
    "SR10 workflow_dispatch given a value": ("fail", [_shape("  workflow_dispatch:\n", "  workflow_dispatch: x\n")]),
    "SR10 run continuation in the proof": ("fail", [_shape(SHAPE_PROOF_CMD, SHAPE_PROOF_CMD.replace(
        " target/release", " \\\n            target/release"))]),
    "X02 proof URL sslmode changed": ("fail", [_shape("55432/proof?sslmode=verify-full", "55432/proof?sslmode=require")]),
    "X03 proof URL sslrootcert changed": ("fail", [_shape("sslrootcert=${PGTLS_DIR}/ca.crt", "sslrootcert=${PGTLS_DIR}/other.crt")]),
    "X19 proof gains a statement after the invocation": ("fail", [_shape(SHAPE_PROOF_CMD, SHAPE_PROOF_CMD + "\n          echo done")]),
    # --- C-1/C-2/SR-11: Dockerfile continuations and spellings
    "C1 canonical build RUN re-indented": ("fail", [_d("    strip target/release/ai-memory; \\", "  strip target/release/ai-memory; \\")]),
    "C1 canonical build RUN joined onto one line": ("fail", [_d("\n".join(DOCKER_RUN_LINES), DOCKER_RUN)]),
    "builder ends with another single-line RUN": ("fail", [_d("\n".join(DOCKER_RUN_LINES), "RUN true")]),
    "C1 continuation in another instruction": ("fail", [_d(D_BIN, D_BIN + "LABEL a=1 \\\n b=2\n")]),
    "4944 continuation with a trailing space in another instruction": ("fail", [_d(D_BIN, D_BIN + "LABEL a=1 \\ \n b=2\n")]),
    "4944 continuation with a trailing tab in another instruction": ("fail", [_d(D_BIN, D_BIN + "LABEL a=1 \\\t\n b=2\n")]),
    "SR11/B05 quoted cargo in the final stage": ("fail", [_d(D_BIN, D_BIN + "RUN c''argo --version\n")]),
    "X11 --mount after another flag": ("fail", [_d(D_BIN, D_BIN + "RUN --network=none --mount=type=cache,target=/m true\n")]),
    "X00 FROM image with an embedded $VAR": ("fail", [_d(D_FINAL, "FROM debian:bookworm-slim$SUFFIX\n")]),
}

# SHAPE_ADVISORY states (C-5): (advisory, want, edits).
ADVISORY_CASES: Dict[str, Tuple[bool, str, List[Edit]]] = {
    "advisory: the plain continue-on-error true passes": (True, "pass", []),
    "advisory: continue-on-error removed": (True, "fail", [(SHAPE, "    continue-on-error: true\n", "", False)]),
    "advisory: continue-on-error quoted": (True, "fail", [(SHAPE, "continue-on-error: true", "continue-on-error: 'true'", False)]),
    "advisory: continue-on-error false": (True, "fail", [(SHAPE, "continue-on-error: true", "continue-on-error: false", False)]),
    "required: continue-on-error still set": (False, "fail", []),
    "required: continue-on-error removed passes": (False, "pass", [(SHAPE, "    continue-on-error: true\n", "", False)]),
}
# C-6: (edits, exact error count, substring of the first message).
MESSAGE_CASES: Dict[str, Tuple[List[Edit], int, str]] = {
    "message: LOGIN_USES SHA bump": ([_rel(LOGIN_USES, LOGIN_USES[:-1] + "0")], 1,
                                     "registry login step): `jobs.docker.steps.3.uses` is"),
    "message: LOGIN_USES SHA bump names the constant": ([_rel(LOGIN_USES, LOGIN_USES[:-1] + "0")], 1,
                                                        "update LOGIN_USES in scripts/check_release_features.py"),
    "message: IMAGE_BUILD_USES SHA bump": ([_rel(IMAGE_BUILD_USES, IMAGE_BUILD_USES[:-1] + "0")], 1,
                                           "update IMAGE_BUILD_USES in scripts/check_release_features.py"),
    "message: a tag added names DOCKER_STEPS": ([_rel(PUSH_TAGS, PUSH_TAGS + "            ghcr.io/o/ai-memory:x\n")], 1,
                                                "update DOCKER_STEPS in scripts/check_release_features.py"),
    "message: build unit drift names WF_BUILD": ([_rel(REL_BUILD_CMD, REL_BUILD_CMD + " --verbose")], 2,
                                                 "update WF_BUILD in scripts/check_release_features.py"),
    "message: 4945 SHA bump plus a changed input is one message naming both": (
        [_rel(IMAGE_BUILD_USES, IMAGE_BUILD_USES[:-1] + "0"), _rel("          context: .\n", "          context: ./evil\n")], 1,
        "update IMAGE_BUILD_USES in scripts/check_release_features.py to the new SHA in the same commit; also "
        "`jobs.docker.steps.5.with.context`"),
    "message: 4945 a quoted uses is not a SHA bump": (
        [_rel("uses: " + IMAGE_BUILD_USES, 'uses: "' + IMAGE_BUILD_USES[:-1] + '0"')], 1,
        "update DOCKER_STEPS in scripts/check_release_features.py"),
    "message: 4945 an extra docker step is one message": (_docker_extra_step("        run: echo\n"), 1,
                                                          "the docker job has 7 steps"),
    "message: 4942 a spaced dotted secret is named whole": (
        _step_before_pkg("        env:\n          T: ${{ secrets . GITHUB_TOKEN }}\n        run: echo\n"), 1,
        "`secrets . GITHUB_TOKEN` is not `secrets.<NAME>`"),
    "message: 4946 a trailing space in the canonical build RUN is one message": (
        [_d("    strip target/release/ai-memory; \\", "    strip target/release/ai-memory; \\ ")], 1,
        "update DOCKER_RUN_LINES in scripts/check_release_features.py"),
    "message: 4946 a re-indented canonical build RUN is one message": (
        [_d("    strip target/release/ai-memory; \\", "  strip target/release/ai-memory; \\")], 1,
        "update DOCKER_RUN_LINES in scripts/check_release_features.py"),
    "message: 4946 the whitelist covers only the canonical RUN's own lines": (
        [_d("    strip target/release/ai-memory; \\", "    strip target/release/ai-memory; \\ "),
         _d(D_BIN, D_BIN + "LABEL a=1 \\\n b=2\n")], 2,
        "update DOCKER_RUN_LINES in scripts/check_release_features.py"),
    "message: 4941 a docker permissions drift is one message naming DOCKER_JOB": (
        [_rel("      packages: write\n      # #2487", "      packages: read\n      # #2487")], 1,
        "update DOCKER_JOB in scripts/check_release_features.py"),
}


# #4944: a tab never reaches the run-line check through the whole guard (the text scan refuses every
# tab, parse_yaml refuses it too, and a decoded `\\t` escape is refused as a backslash in a
# double-quoted scalar), so the tab half of its `rstrip(" \\t")` is pinned on hand-built nodes.
RUN_LINE_UNITS: Tuple[Tuple[str, Tuple[str, ...], int], ...] = (
    ("a run line ending in a backslash and a tab", ("echo a \\\t", "echo b"), 1),
    ("a run line ending in a backslash and a space", ("echo a \\ ", "echo b"), 1),
    ("a run line with a backslash inside, not last", ("echo a\\b\t", "echo b"), 0),
)


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


# BuildKit parity (expected outputs recorded from the moby/buildkit v0.23.2 dockerfile parser):
# (physical lines, buildkit mode, logical lines).
PARITY: Tuple[Tuple[Tuple[str, ...], bool, Tuple[str, ...]], ...] = (
    (("FROM a", "VOLUME /data \\", "", "COPY x y"), True, ("FROM a", "VOLUME /data COPY x y")),
    (("RUN echo \\", "# c", "  b"), True, ("RUN echo b",)),
    (("RUN a \\  ", "b"), True, ("RUN a b",)),
    (("RUN echo \\",), True, ("RUN echo",)),
    (("FROM img", "\\"), True, ("FROM img", "")),
    (("FROM img", "  \\  "), True, ("FROM img", "")),
    (("# x", "", "  # y", "RUN  a\tb"), True, ("RUN a b",)),
    (("label x=1",), True, ("label x=1",)),
    (("a \\", "# c", "b"), False, ("a # c", "b")),
    (("a \\", "", "b"), False, ("a", "b")),
    (("RUN ca\\", "rgo"), True, ("RUN cargo",)),
    (("RUN ca\\", "  rgo"), True, ("RUN ca rgo",)),
    (("RUN a\\\\", "b"), True, ("RUN a\\\\", "b")),
    (("ca\\", "rgo"), False, ("cargo",)),
    (("a \\ ", "b"), False, ("a \\", "b")),
    (("a\\\\", "b"), False, ("a\\\\", "b")),
)
# YAML scalar decoding: (document, key, expected text or None when the document is refused).
SCALARS: Tuple[Tuple[str, str, Optional[str]], ...] = (
    ("a: 'it''s'\n", "a", "it's"),
    ("a: ''''\n", "a", "'"),
    ('a: "plain"\n', "a", "plain"),
    ('a: "x\\x63y"\n', "a", None),
    ('a: "x\\"y"\n', "a", None),
    ("a: 'x\\y'\n", "a", "x\\y"),
    ("a: plain\n", "a", "plain"),
)


def unit_checks() -> int:
    """Pure-function cases: logical_lines parity with BuildKit, noise detection, scalar decoding."""
    failures = 0
    for lines, bk, want in PARITY:
        got = tuple(logical_lines(list(lines), buildkit=bk))
        if got != want:
            print(f"self-test FAIL: logical_lines({list(lines)}, buildkit={bk}) = {list(got)}, wanted {list(want)}", file=sys.stderr)
            failures += 1
    if continuation_noise(["RUN a \\", "", "# c", "b", "# d"]) != [2, 3]:
        print("self-test FAIL: continuation_noise misses a blank or comment inside a continuation", file=sys.stderr)
        failures += 1
    if continuation_noise(["# a", "", "RUN a \\", "b", "", "# d"]):
        print("self-test FAIL: continuation_noise flags a line outside a continuation", file=sys.stderr)
        failures += 1
    if bk_instructions(list(DOCKER_RUN_LINES)) != [(1, len(DOCKER_RUN_LINES), DOCKER_RUN)]:
        print("self-test FAIL: DOCKER_RUN_LINES does not join to DOCKER_RUN", file=sys.stderr)
        failures += 1
    for doc, key, want in SCALARS:
        rep = Report()
        node = parse_yaml(doc, "scalar", rep)
        got: Optional[str] = None
        if node is not None and not rep.errors:
            val = node.get(key)
            got = val.text() if val is not None else None
        if got != want:
            print(f"self-test FAIL: scalar {doc!r} decoded {got!r}, wanted {want!r}", file=sys.stderr)
            failures += 1
    return failures


def self_test(root: Path) -> int:
    failures = unit_checks()
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

        for name, (advisory, want, edits) in ADVISORY_CASES.items():
            case_root = tmp / "case"
            mk_root(root, case_root)
            for rel, old, new, every in edits:
                mutate_file(case_root / rel, old, new, every)
            errs, _ = run_guard(case_root, advisory)
            if ("fail" if errs else "pass") != want:
                print(f"self-test FAIL: '{name}' wanted {want}: {errs[:2]}", file=sys.stderr)
                failures += 1
        for name, (edits, count, needle) in MESSAGE_CASES.items():
            case_root = tmp / "case"
            mk_root(root, case_root)
            for rel, old, new, every in edits:
                mutate_file(case_root / rel, old, new, every)
            errs, _ = run_guard(case_root)
            if len(errs) != count or needle not in errs[0]:
                print(f"self-test FAIL: '{name}' wanted {count} message(s) containing {needle!r}: {errs[:3]}",
                      file=sys.stderr)
                failures += 1

        # --- the run-line check on its own (a tab cannot reach it through the whole guard).
        for name, lines, want_n in RUN_LINE_UNITS:
            rep_u = Report()
            doc_u = Node("map", 0, {"run": Node("block", 0, list(lines), "|")})
            check_run_continuations(doc_u, "unit.yml", rep_u)
            if len(rep_u.errors) != want_n:
                print(f"self-test FAIL: run-line unit '{name}' wanted {want_n} message(s): {rep_u.errors[:2]}",
                      file=sys.stderr)
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
        f"{len(CASES)} guard cases, {len(ADVISORY_CASES)} advisory cases, {len(MESSAGE_CASES)} message cases, "
        f"{len(PARITY)} parity cases, {len(SCALARS)} scalar cases, {len(RUN_LINE_UNITS)} run-line unit cases, {len(ENTRY_CASES)} entry-point cases)"
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
    cond_total, cond_survivors = condition_sweep(root, src)
    print(f"check_release_features: mutation sweep: {len(results)} refusal mutants + {cond_total} condition mutants = "
          f"{len(results) + cond_total} mutants, {len(survivors) + len(cond_survivors)} survivors")
    if survivors or cond_survivors:
        print(f"check_release_features: surviving refusal sites at lines {survivors}, condition mutants {cond_survivors}",
              file=sys.stderr)
        return 1
    return 0


def condition_sweep(root: Path, src: bytes) -> Tuple[int, List[str]]:
    """Apply each CONDITION_MUTANTS entry (exact-once text substitution above CONDITION_MARKER)
    and require ``--self-test`` to fail. An anchor that is not found exactly once is itself a survivor."""
    me = Path(__file__).resolve()
    text = src.decode("utf-8")
    cut = text.index(CONDITION_MARKER + "\n")
    head, tail = text[:cut], text[cut:]
    base = os.environ.get("TMPDIR") or str(root / ".local-runs")
    Path(base).mkdir(parents=True, exist_ok=True)
    survivors: List[str] = []
    with tempfile.TemporaryDirectory(prefix="relfeat-cond.", dir=base) as td:
        tmp = Path(td)

        def run(item: Tuple[int, Tuple[str, str, str]]) -> Tuple[int, str, str]:
            k, (desc, old, new) = item
            if head.count(old) != 1:
                return k, desc, f"SURVIVED (anchor found {head.count(old)} times, not once)"
            mutant = tmp / f"cond_{k}.py"
            mutant.write_text(head.replace(old, new, 1) + tail, encoding="utf-8")
            res = subprocess.run([sys.executable, str(mutant), "--self-test", str(root)], capture_output=True, text=True)
            return k, desc, "killed" if res.returncode != 0 else "SURVIVED"

        with ThreadPoolExecutor(max_workers=max(1, min(4, os.cpu_count() or 1))) as pool:
            results = sorted(pool.map(run, list(enumerate(CONDITION_MUTANTS))))
    for k, desc, state in results:
        print(f"condition {k:3d} {desc}: {state}")
        if state != "killed":
            survivors.append(f"{k} ({desc})")
    del me
    return len(results), survivors




# Condition mutants: (description, anchor, replacement). The sweep above only neutralises refusal CALLS;
# these change a CONDITION or a regex, which that sweep cannot see. Each anchor must occur exactly once in
# the source ABOVE the marker line below (so the table never matches itself); the mutant is killed when
# --self-test exits non-zero.
CONDITION_MARKER = "# --- end of condition mutants"
# --- end of condition mutants
CONDITION_MUTANTS: Tuple[Tuple[str, str, str], ...] = (
    ("double-quoted backslash test never fires", 'if style == "double" and "\\\\" in v:', "if False:"),
    ("single-quoted '' is not decoded", 'v[1:-1].replace("\'\'", "\'")', "v[1:-1]"),
    ("single-quoted style test never fires", 'if style == "single":', "if False:"),
    ("continuation noise never recorded", "            if open_:\n", "            if False:\n"),
    ("--mount refusal is case-sensitive", '"--mount" in ins.lower()', '"--mount" in ins'),
    ("--mount refused only right after RUN", 'if "--mount" in ins.lower():', 'if ins.lower().startswith("run --mount"):'),
    ("FROM variable refusal never fires", 'if "$" in image:', "if False:"),
    ("FROM variable refusal sees only ${", 'if "$" in image:', 'if "${" in image:'),
    ("empty instruction at end of file inside a continuation dropped", "    if buf is not None:\n        out.append((start, len(lines), _collapse(buf)))", "    if buf is not None and buf.strip(\" \\t\"):\n        out.append((start, len(lines), _collapse(buf)))"),
    ("instruction word is not case-folded", 'word = ins.split(" ", 1)[0].upper()', 'word = ins.split(" ", 1)[0]'),
    ("final-stage binary COPY count not compared", "if len(copies) != 1:", "if False:"),
    ("proof order against the build not compared", "if builds and proofs and proofs[0] < builds[0]:", "if False:"),
    ("proof URL placeholder accepts any URL", "SHAPE_URL_RE.fullmatch(lines[1])", "True"),
    ("proof norm drops statements after the URL", "if len(lines) == len(SHAPE_PROOF) and SHAPE_URL_RE", "if len(lines) >= 3 and SHAPE_URL_RE"),
    ("proof URL sslmode not pinned", r"\?sslmode=verify-full", r"\?sslmode=[a-z-]+"),
    ("proof URL sslrootcert not pinned", r"&sslrootcert=\$\{PGTLS_DIR\}/ca\.crt", r"&sslrootcert=[^\"]*"),
    ("pinned step name expression allowed", 'if name is not None and "${{" in name.text():\n        why.bad("the step', 'if False:\n        why.bad("the step'),
    ("quoted build tool spelling not unquoted (release job)", "BUILD_TOOL_RE.search(unquoted(t))", "BUILD_TOOL_RE.search(t)"),
    ("quoted build tool spelling not unquoted (Dockerfile)", "BUILD_TOOL_RE.search(unquoted(ins))", "BUILD_TOOL_RE.search(ins)"),
    ("KEY_RE accepts a space before the colon", 'KEY_RE = re.compile(r"(?P<key>[A-Za-z_][A-Za-z0-9_-]*):', 'KEY_RE = re.compile(r"(?P<key>[A-Za-z_][A-Za-z0-9_-]*) ?:'),
    ("SHAPE_ADVISORY flipped", "SHAPE_ADVISORY = True", "SHAPE_ADVISORY = False"),
    ("advisory default ignored", "        advisory = SHAPE_ADVISORY\n", "        advisory = False\n"),
    ("advisory branch always taken", "    if advisory:\n", "    if True:\n"),
    ("required state never refuses the key", "    elif coe is not None:\n", "    elif False:\n"),
    ("pinned scalar style not compared", 'node.kind == "scalar" and node.style == style and', 'node.kind == "scalar" and'),
    ("pinned block style not compared", 'node.kind == "block" and node.style == "|" and', 'node.kind == "block" and'),
    ("pinned mapping key set not compared", "if set(node.keys()) != set(spec):", "if False:"),
    ("pinned sequence length not compared", "if items is None or len(items) != len(spec):", "if items is None:"),
    ("pinned no-value key not compared", 'return "" if node.kind == "null" else', 'return "" if True else'),
    ("docker step count not compared", "if len(items) != len(DOCKER_STEPS):", "if False:"),
    ("action SHA bump not recognised", 'uses.text().split("@")[0] == want.split("@")[0]', "False"),
    ("canonical RUN physical lines not compared", "if tuple(raw[first - 1:last]) == DOCKER_RUN_LINES:", "if True:"),
    ("continuations outside the canonical RUN allowed", "        if n not in canon_lines:\n", "        if False:\n"),
    ("run continuation check never fires", 'if text.rstrip(" \\t").endswith("\\\\"):', "if False:"),
    ("registry allowed outside the docker job", "if not in_docker and REGISTRY in text.lower():", "if False:"),
    ("registry name compared case-sensitively", "REGISTRY in text.lower()", "REGISTRY in text"),
    ("secret name not compared", 'm.group("name") not in RELEASE_SECRETS or ', ""),
    ("secret reference shape not compared", ' or m.group(0) != "secrets." + str(m.group("name"))', ""),
    ("secrets key never refused", 'if path and path[-1].lower() == "secrets":', "if False:"),
    ("reusable workflow job never refused", 'if job.get("uses") is not None:', "if False:"),
    ("shell join on any trailing backslash", '(len(raw) - len(raw.rstrip("\\\\"))) % 2 == 1', 'raw.endswith("\\\\")'),
    ("BuildKit join strips the next line's indent", "            piece = raw\n", '            piece = raw.lstrip(" \\t")\n'),
    ("BuildKit continuation needs a bare backslash", r'BK_CONT_RE = re.compile(r"(^|[^\\])\\[ \t]*$")', r'BK_CONT_RE = re.compile(r"(^|[^\\])\\$")'),
    ("BuildKit continuation on an escaped backslash", r'(^|[^\\])\\[ \t]*$', r'\\[ \t]*$'),
    ('SHA-bump branch accepts quoted uses', 'uses.kind == "scalar" and uses.style == "plain"\n', 'uses.kind == "scalar"\n'),
    ('SHA-bump branch does not compare the rest of the step', '        why = pin_problem(step, rest, at)\n', '        why = ""\n'),
    ('SECRET_REF_RE case-sensitive', 'A-Za-z0-9_]*))?", re.I)', 'A-Za-z0-9_]*))?")'),
    ('SECRET_REF_RE no lookbehind', 'r"(?<![\\w.-])secrets(?![\\w-])', 'r"secrets(?![\\w-])'),
    ('SECRET_REF_RE spaces not allowed around dot', '(?P<ref>\\s*\\.\\s*(?P<name>', '(?P<ref>\\.(?P<name>'),
    ('secrets key case-sensitive', 'if path and path[-1].lower() == "secrets":', 'if path and path[-1] == "secrets":'),
    ('shape BASH_ENV text check removed', '    check_no_bash_env("release-shape.yml", text, rep)\n', ''),
    ('shape top keys compared as a set', '    if doc.keys() != list(SHAPE_TOP_KEYS):', '    if set(doc.keys()) != set(SHAPE_TOP_KEYS):'),
    ('continued_lines ignores trailing tabs/spaces', 'if raw.rstrip(" \\t").endswith("\\\\")]', 'if raw.endswith("\\\\")]'),
    ('run continuation ignores trailing spaces', 'if text.rstrip(" \\t").endswith("\\\\"):', 'if text.endswith("\\\\"):'),
    ('pin_problem sequence compares only the first item', '            why = pin_problem(item, sub, f"{path}.{n + 1}")\n            if why:\n                return why\n', '            why = pin_problem(item, sub, f"{path}.{n + 1}")\n            return why\n'),
    ('docker step count mismatch: no early return (more messages)', '                            f"first difference is step {first + 1}", "DOCKER_STEPS"))\n        return\n', '                            f"first difference is step {first + 1}", "DOCKER_STEPS"))\n'),
    ("workflow run continuation strips spaces only (#4944)", 'if text.rstrip(" \\t").endswith("\\\\"):', 'if text.rstrip(" ").endswith("\\\\"):'),
    ("#4946 whitelist widened to the whole file", "                canon_lines.update(set(range(first, last + 1)))\n", "                canon_lines.update(set(range(1, len(raw) + 1)))\n"),
    ("docker permissions pinned twice: RELEASE_JOB_PERMISSIONS again (#4941 F1)", '        if name == "docker":\n', '        if False:\n'),
    ("canonical RUN written differently: its lines not whitelisted (#4946)", "                canon_lines.update(set(range(first, last + 1)))\n", "                pass\n"),
)


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
