# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Issue #9681: chain/** pull requests restore a dependency cache that only a push writes.

Invariant (for every job with a Swatinem/rust-cache step in every workflow a pull request can
start): a cache is written only by a run on a pushed branch, never by a ``pull_request`` or
``merge_group`` run. Every rust-cache step carries exactly
``save-if: ${{ github.event_name == 'push' }}``; no combined ``actions/cache`` step (whose post
step saves on every event) runs in such a workflow; every ``actions/cache/save`` step is gated on
``github.event_name == 'push'``.

The save path for chain/** is ``.github/workflows/rust-cache-warm.yml``: a push-only workflow on
GitHub-hosted ``ubuntu-latest`` (never the fed self-hosted runners, never a second full run). Each
of its jobs writes the cache key one pull-request job restores: the same ``shared-key``, the same
toolchain action and inputs, and the same CARGO*/RUST*/CC*/CFLAGS*/CXX*/CMAKE* environment at the
cache step (rust-cache hashes those into the key), plus the same build-affecting environment after
it so the restored artifacts are reused.

The touched workflows keep every job id, job name and test step (hand tables below, d54c4b0e):
required contexts are unchanged, and the same tests run.

Vote V2-9681 (3-agent vote 71472661, A+ push-only hosted warm workflow on chain/**): the chain
cache has exactly one writer, rust-cache-warm.yml (push on chain/** only, GitHub-hosted, no
secrets, sha-pinned actions); no other workflow can write or share its keys; one prefix-key
generation constant at the six paired cache steps (#9732 added the android leg pair) invalidates it. ``ChainCacheSoleWriter9681``
holds conditions V-2 to V-11 over every workflow file, not over hand tables.

Run: python3 -I -m unittest discover -s scripts/ci/tests -p 'test_rust_cache_save_scope_9681.py'
"""

from __future__ import annotations

import re
import shlex
import sys
import time
import unittest
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
WORKFLOWS = REPO / ".github" / "workflows"
REQUIRED_CONTEXTS = REPO / "scripts" / "qc-allowlists" / "required-contexts-release.txt"
WARM = "rust-cache-warm.yml"

RUST_CACHE = "Swatinem/rust-cache"
RUST_CACHE_SHA = "6323deb102c322ba6fcbdcafc7e3dddab59af2b6"
SAVE_IF_PUSH = "${{ github.event_name == 'push' }}"
CACHE_COMBINED = "actions/cache"
CACHE_RESTORE = "actions/cache/restore"
CACHE_SAVE = "actions/cache/save"
PUSH_GATE = "github.event_name == 'push'"
PR_EVENTS = frozenset({"pull_request", "merge_group", "pull_request_target"})
# rust-cache@6323deb (src/config.ts) hashes every non-empty variable with these prefixes.
KEY_ENV_PREFIXES = ("CARGO", "CC", "CFLAGS", "CXX", "CMAKE", "RUST")
FED_LABEL_RE = re.compile(r"self-hosted|fed|macos|windows|arm|matrix", re.IGNORECASE)
STEP_INDENT = 6
KEY_INDENT = 8

# --- hand tables (d54c4b0e): written from the workflows at fd43a727, never derived ---------------

# Every workflow a pull request can start that has a rust-cache step, with the number of
# rust-cache steps in each of its jobs.
RUST_CACHE_SITES: dict[str, dict[str, int]] = {
    "ci.yml": {"lint": 1, "check": 1, "postgres-feature": 1, "mobile-cross-compile": 1,
               "sal-feature": 1, "vectorlite-feature": 1},
    "coverage.yml": {"per-module-thresholds": 1},
    "batman-mode-acceptance.yml": {"rust-integration": 1, "bash-integration": 1},
    "bench.yml": {"bench": 1, "regenerate-baseline": 1},
    "cert-postgres-age.yml": {"cert-postgres-age": 1},
    "mobile-runtime.yml": {"ios-simulator": 1, "android-emulator": 1},
    "release-shape.yml": {"release-shape": 1},
    "token-budget.yml": {"budget": 1},
}

# Push-trigger branches of every touched workflow. No PR-time workflow gains chain/**: a push
# there would start the fed self-hosted legs and the PG coverage suite a second time.
PUSH_BRANCHES: dict[str, tuple[str, ...]] = {
    "ci.yml": ("main", "develop", "release/**"),
    "coverage.yml": ("main", "develop", "feat/v0.7.0-grand-slam", "release/**"),
    "batman-mode-acceptance.yml": ("main", "develop", "release/**"),
    "bench.yml": ("main", "develop", "release/**"),
    "cert-postgres-age.yml": ("release/**",),
    "mobile-runtime.yml": ("release/**",),
    "release-shape.yml": ("release/**",),
    "token-budget.yml": ("main", "develop", "release/**"),
    WARM: ("chain/**",),
}

# Job id -> job name of every job of every touched workflow.
JOBS: dict[str, dict[str, str]] = {
    "ci.yml": {
        "select": "Impact selection",
        "classify": "Classify changes",
        "lint": "Lint (fmt + clippy)",
        "build-script-vetting": "Build-script custom-build ledger gate (#2635)",
        "actionlint": "actionlint (workflow-injection guard)",
        "msrv": "MSRV (Rust 1.98)",
        "check": "Check (${{ matrix.leg }})",
        "postgres-feature": "Postgres feature gate",
        "mobile-cross-compile": "Cross-compile (${{ matrix.target }})",
        "sal-feature": "SAL-only feature gate",
        "vectorlite-feature": "vectorlite feature gate",
        "dockerfile-validate": "Dockerfile build (no push)",
        "ci-gate": "ci-gate",
    },
    "coverage.yml": {
        "classify": "Coverage classify (docs-only short-circuit)",
        "per-module-thresholds": "Per-Module Coverage Thresholds",
    },
    "batman-mode-acceptance.yml": {
        "rust-integration": "Rust integration (issue_800_batman_mode)",
        "bash-integration": "Bash integration (test-batman-mode-suite.sh)",
        "surface-stability": "Surface stability (load-bearing symbols)",
    },
    "bench.yml": {
        "bench": "ai-memory bench (ubuntu-latest)",
        "regenerate-baseline": "Regenerate bench baseline (ubuntu-latest, median-of-3)",
    },
    "cert-postgres-age.yml": {
        "cert-postgres-age": "Certified pg+AGE cells (live PG 18.6 + AGE 1.8.0 + pgvector 0.8.6)",
    },
    "mobile-runtime.yml": {
        "ios-simulator": "iOS Simulator runtime",
        "android-emulator": "Android emulator runtime",
    },
    "release-shape.yml": {
        "release-shape": "Release-shaped build + PG TLS proof",
    },
    "token-budget.yml": {
        "budget": "token-budget gates",
    },
    WARM: {
        "check-hosted-sqlite": "Rust cache warm (Check ubuntu-latest,sqlite deps)",
        "coverage": "Rust cache warm (Per-Module Coverage deps)",
        "mobile-android-audit-release": "Rust cache warm (Cross-compile android audit+release deps)",
    },
}

# ci-gate folds these jobs (the others are required contexts by their own names); a step moved
# into a job outside this list and outside the required contexts stops failing a required context.
CI_GATE_NEEDS = ("select", "classify", "build-script-vetting", "check", "mobile-cross-compile")

# Job -> ordered labels of its test and gate steps (run text matching TEST_RUN_RE). A plain YAML
# step name ends at ` #`, so some labels below stop mid-parenthesis exactly as GitHub shows them.
TEST_STEPS: dict[str, dict[str, tuple[str, ...]]] = {
    "ci.yml": {
        "select": ("Materialise the base selector (#8240)",),
        # #9593 (chain tip 407c2c7e) moved the two replay-object fetches and the #6344 shard unit
        # tests from `classify` to the end of `build-script-vetting` (#9737).
        "classify": ("run: # TWO SEPARATE BASES (#2496). Sharing one was the defect.",
                     "run: emit_all() {",
                     "Test impact selector security fallbacks",
                     "Workflow concurrency invariants (#6340)",
                     "AGE self-heal helper unit test (#6161)",
                     "Target sweep unit tests (#7160)"),
        "lint": ("Check formatting", "Clippy",
                 "Clippy (all targets, sal — cfg-stripped doc-lint class)"),
        "build-script-vetting": ("Verify every custom-build package is ledgered",
                                 "Self-test (prove the gate is load-bearing)",
                                 "Fetch the corpus replay objects (#7988)",
                                 "Fetch the amendment ledger replay objects (#9303)",
                                 "Shard partition and wiring unit tests (#6344)"),
        "actionlint": (),
        "msrv": (),
        "check": ("Per-runner cargo target (#7188)",
                  "sccache build cache (#7199)",
                  "Free disk before tests (hosted image only,",
                  "Prebuild t0 orchestrator (macOS e1 anti-flake,",
                  "Configure enterprise-fed tier (per-job ephemeral db, enterprise-fed legs only)",
                  "Run the pg_isolated_binary live cells (enterprise-fed legs only)",
                  "Load gate (#6795)",
                  "Run tests (impact-aware)",
                  "Cleanup enterprise-fed ephemeral db",
                  "sccache hit-rate summary (#7199)",
                  "sccache stop CI server (#7199)",
                  "Prune stale runner artifacts (#7188)",
                  "Sweep target/debug to the size cap (self-hosted)",
                  "Sweep per-runner cargo target to the size cap (self-hosted,"),
        "postgres-feature": ("Clippy (sal-postgres feature, lib + tests)",),
        # #9680 moved `Security audit` and the release smoke from `check` to the android entry.
        "mobile-cross-compile": ("cargo check (--lib --features sqlite-bundled)",
                                 "Security audit",
                                 "Build release (once leg — release-profile smoke)"),
        "sal-feature": ("Clippy (sal feature)", "Build release (sal feature)",
                        "Run lib tests (sal feature)"),
        "vectorlite-feature": ("Clippy (vectorlite feature, all targets)",
                               "Run vectorlite no-native-lib seam tests (#1860)",
                               "Run config-precedence under vectorlite (#2256 feature-gated pin)"),
        "dockerfile-validate": (),
        "ci-gate": ("Materialise the base gate (#8240)",
                    "Fold job results (bootstrap, PR-tree gate)",
                    "Fold job results (branch tip gate)"),
    },
    "coverage.yml": {
        "classify": ("run: # LOAD-BEARING (#2496): on `pull_request` this base is the PR",),
        "per-module-thresholds": ("PostgreSQL package repair + preflight (#9235)",
                                  "Generate coverage JSON"),
    },
    "batman-mode-acceptance.yml": {
        "rust-integration": ("Build release binary", "Compose stack boot smoke (#3838)",
                             "init-batman api_key rewrite fixtures (#4291)",
                             "Run Batman Mode regression tests",
                             "Run Form 7 agent-EXTERNAL wiring tests (regression cordon)"),
        "bash-integration": ("Build release binary + install to PATH",
                             "Run Batman Mode bash integration suite (quick mode)"),
        "surface-stability": (),
    },
    "bench.yml": {
        "bench": ("Build release binary",),
        "regenerate-baseline": ("Build release binary", "Capture median-of-3 baseline"),
    },
    "cert-postgres-age.yml": {
        "cert-postgres-age": ("Run", "Cluster-A cert-posture armability gate (#3061",
                              "Redact cert-bootstrap evidence on failure",
                              "Sweep target/debug to the size cap (self-hosted)"),
    },
    "mobile-runtime.yml": {
        "ios-simulator": ("Build mobile_runtime test binary for iOS Simulator",),
        "android-emulator": ("Build mobile_runtime test binary for Android (x86_64)",),
    },
    "release-shape.yml": {
        "release-shape": ("Release feature declaration guard",
                          "Build release binary (exactly as release.yml)",
                          "No OpenSSL / libpq / native-tls in the shipped dependency graph",
                          "Prove the shipped binary reports sal-postgres and uses the tier over "
                          "verify-full"),
    },
    "token-budget.yml": {
        "budget": ("per-tool ceiling (1500 tokens cl100k_base)",
                   "full-profile honest range (5K–8K cl100k_base)",
                   "doctor --tokens default-profile-is-core",
                   "full-profile <= 8110 tokens (v0.7 C5 hard ceiling, post-D1.6 +",
                   "doctor --tokens --json reports trimmed total <= 8110 (v0.7 C5 post-D1.6 +"),
    },
}

# (PR workflow, PR job, warm job, shared-key): the warm job writes the key the PR job restores.
PAIRS = (
    ("ci.yml", "check", "check-hosted-sqlite", "ci-check-hosted-sqlite"),
    ("coverage.yml", "per-module-thresholds", "coverage", "coverage-per-module"),
)

# #9732: one hosted matrix leg of a PR job whose other legs stay unpaired. Site key (workflow, job,
# leg id) -> (warm job, shared-key). The PR job spells the key once for every leg, so the template
# below resolves per leg to the literal the warm job spells; test_chain_android_cache_9732.py pins
# the pair (steps, key env, cargo commands) the way WarmCommandList9681 pins PAIRS.
LEG_PAIRS: dict[tuple[str, str, str], tuple[str, str]] = {
    ("ci.yml", "mobile-cross-compile", "target=aarch64-linux-android"): (
        "mobile-android-audit-release", "mobile-aarch64-linux-android-audit-release"),
}
LEG_SHARED_KEY_TEMPLATES: dict[tuple[str, str], str] = {
    ("ci.yml", "mobile-cross-compile"): "mobile-${{ matrix.target }}-audit-release",
}

# Steps before the cache step that may export to GITHUB_ENV in a PR job of PAIRS (none of them
# runs on the hosted leg: each is gated on a self-hosted-only matrix field), and the
# post-cache GITHUB_ENV steps the warm job must mirror byte for byte.
PRE_CACHE_ENV_STEPS: dict[tuple[str, str], tuple[str, ...]] = {
    ("ci.yml", "check"): ("Record job start (#6795)", "Per-runner cargo target (#7188)",
                          "sccache build cache (#7199)"),
    ("coverage.yml", "per-module-thresholds"): (),
}
MIRRORED_STEPS: dict[tuple[str, str], tuple[str, ...]] = {
    ("ci.yml", "check"): (
        "Free disk before tests (hosted image only,",
        "actions/setup-python",
        "actions/setup-node",
        "Install Rust 1.99.1 (matches rust-toolchain.toml pin)",
        "Low-mem hosted sqlite link (debuginfo=0, system ld — mold isolation)",
    ),
    ("coverage.yml", "per-module-thresholds"): (
        "Free disk + add swap (#1148 belt-and-suspenders, aggressive)",
        "Install Rust 1.99.1",
        "Install mold linker (#1148, pinned+bounded",
        "Install cargo-llvm-cov",
    ),
}
# The cargo commands of each pair are derived, not listed: WarmCommandList9681 compares the
# exact command lines of the hosted PR legs and the warm job in both directions. Since #9680
# the hosted `check` leg runs neither `cargo build --release` nor `cargo install cargo-audit`
# (both moved to the android entry of `mobile-cross-compile`, which is not a PAIRS job), so a
# warm copy of either is an only-in-warm-job finding.

# HuggingFace model cache of coverage.yml: restore on every event, save on push only.
HF_CACHE_SITES = {
    ("coverage.yml", "per-module-thresholds"): ("Restore HuggingFace models (#2019)",
                                                "Save HuggingFace models (#2019, push only)"),
    (WARM, "coverage"): ("Restore HuggingFace models (#2019)",
                         "Save HuggingFace models (#2019, push only)"),
}

# --- vote V2-9681 conditions (whole-repository scans, no per-file hand table) --------------------

CHAIN_PREFIX = "chain/"
# Refs a chain push can carry; a push filter that matches any of them reaches the chain scope.
CHAIN_SAMPLE_REFS = ("chain/promo6-ssh-r2", "chain/a/b", "chain/x")
GLOB_CHARS = frozenset("*?+[]!")
# Steps whose text marks a workflow that builds or publishes release artefacts.
RELEASE_ARTEFACT_RE = re.compile(
    r"actions/upload-artifact|softprops/action-gh-release|actions/attest|attest-build-provenance"
    r"|docker/build-push-action|\bdocker push\b|\bgh release (?:create|upload)\b|\bcargo publish\b"
    r"|\bnpm publish\b|\btwine upload\b|id-token:\s*write")
# The keys the chain PR jobs restore; they may appear only in the paired workflows.
SHARED_KEYS = (*(pair[3] for pair in PAIRS), *(pair[1] for pair in LEG_PAIRS.values()))
KEY_HOLDERS = frozenset({"ci.yml", "coverage.yml", WARM})
# Workflows started by these events run with a base-branch token and may write the base cache.
PRIVILEGED_EVENTS = frozenset({"pull_request_target", "workflow_run"})
CACHE_USES_RE = re.compile(r"""^\s*(?:-\s+)?uses:\s*['"]?(Swatinem/rust-cache|actions/cache)(?:[/@]|['"]?\s*$)""")
USES_RE = re.compile(r"""^\s*(?:-\s+)?uses:\s*['"]?([^'"\s#]+)""")
PINNED_USES_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$")
WARM_FORBIDDEN_RE = re.compile(r"upload-artifact|id-token|\bsecrets\s*[.:\[]")
# V-7: one generation constant at the six paired cache steps; a bump changes every chain key.
PREFIX_KEY_RE = re.compile(r"^chain-cache-g[1-9][0-9]*$")
HOSTED_GUARD = "runner.environment == 'github-hosted'"
CI_GATE_JOB = ("ci.yml", "ci-gate")
BRANCH_PROTECTION = REPO / ".github" / "branch-protection.yml"
CHANGELOG_9681 = REPO / "changelog.d" / "9681.changed.md"
# V-2: the header names the precedents and why this push trigger is the one exception.
V2_HEADER_PHRASES = ("#2506", "#2523", "#2508", "the one sanctioned exception")
# V-11: the kill switch and the revert rule, in the header and in the changelog entry.
V11_PHRASES = ("Kill switch:", "delete the caches of the chain ref", "revert this workflow",
               "build.rs", "a proc-macro crate", ".cargo/", "Cargo.lock",
               "bumps the prefix-key generation constant in the same merge")


# --- a small indentation parser for the workflow shapes this repository uses --------------------


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _is_comment_or_blank(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def _scalar(raw: str) -> str:
    value = raw.strip()
    if value[:1] in ("'", '"') and value[-1:] == value[:1] and len(value) >= 2:
        return value[1:-1]
    if " #" in value:
        value = value.split(" #", 1)[0].rstrip()
    return value


def _flow_list(raw: str) -> tuple[str, ...]:
    inner = raw.strip()
    if not (inner.startswith("[") and inner.endswith("]")):
        return (_scalar(inner),)
    return tuple(_scalar(part) for part in inner[1:-1].split(",") if part.strip())


@dataclass
class Step:
    lines: list[str]
    keys: dict[str, str] = field(default_factory=dict)
    blocks: dict[str, list[str]] = field(default_factory=dict)

    def label(self) -> str:
        """The step name as YAML reads it (a plain scalar ends at ` #`), else its action, else
        the first line of its run text."""
        if self.keys.get("name"):
            return self.keys["name"]
        if self.uses_name():
            return self.uses_name()
        first = next((line for line in self.run().splitlines() if line.strip()), "")
        return "run: " + first.strip()

    def uses_name(self) -> str:
        return self.keys.get("uses", "").split("@", 1)[0]

    def mapping(self, key: str) -> dict[str, str]:
        return _mapping(self.blocks.get(key, []), KEY_INDENT + 2)

    def run(self) -> str:
        return "\n".join(line[KEY_INDENT + 2:] for line in self.blocks.get("run", [])).strip("\n")


def _parse_step(lines: list[str]) -> Step:
    step = Step(lines=lines)
    first = " " * KEY_INDENT + lines[0].strip()[2:]
    body = [first, *lines[1:]]
    current = ""
    for line in body:
        if current == "run" and line.strip() and _indent(line) <= KEY_INDENT \
                and line.lstrip().startswith("#"):
            # A less-indented comment ends a YAML block scalar: it is not run text.
            current = ""
            continue
        if _is_comment_or_blank(line) and current != "run":
            continue
        if _indent(line) == KEY_INDENT and not line.strip().startswith("#"):
            name, _, value = line.strip().partition(":")
            current = name
            value = value.strip()
            if value in ("|", ">", "|-", ">-", ""):
                step.blocks[name] = []
            else:
                step.keys[name] = _scalar(value)
                step.blocks[name] = []
            continue
        if current:
            step.blocks.setdefault(current, []).append(line)
    if "run" in step.keys:
        step.blocks["run"] = [" " * (KEY_INDENT + 2) + step.keys["run"]]
    return step


@dataclass
class Job:
    job_id: str
    lines: list[str]

    def scalar(self, key: str) -> str | None:
        for line in self.lines:
            if _indent(line) == 4 and line.strip().startswith(key + ":"):
                return _scalar(line.strip()[len(key) + 1:])
        return None

    def block(self, key: str) -> list[str]:
        out: list[str] = []
        inside = False
        for line in self.lines:
            if _is_comment_or_blank(line):
                if inside:
                    out.append(line)
                continue
            if _indent(line) == 4:
                inside = line.strip().startswith(key + ":")
                if inside and line.strip()[len(key) + 1:].strip():
                    out.append(" " * 6 + line.strip()[len(key) + 1:].strip())
                continue
            if inside:
                out.append(line)
        return out

    def env(self) -> dict[str, str]:
        return _mapping(self.block("env"), 6)

    def steps(self) -> list[Step]:
        lines = self.block("steps")
        steps: list[list[str]] = []
        for line in lines:
            if _indent(line) == STEP_INDENT and line.lstrip().startswith("- "):
                steps.append([line])
            elif steps:
                steps[-1].append(line)
        return [_parse_step(item) for item in steps]


class SourceStr(str):
    """A mapping value as the lenient reader cut it, plus what the strict decoder needs: `source`
    is the text after the colon (comment included) and `nested` is the first deeper line below
    the key ("" when none). #9745 r1: an env value is decoded from `source`, never from the cut."""

    source: str
    nested: str

    def __new__(cls, text: str, source: str = "", nested: str = "") -> SourceStr:
        obj = super().__new__(cls, text)
        obj.source = source
        obj.nested = nested
        return obj


def _nested_line(rest: list[str], indent: int) -> str:
    """The first non-blank, non-comment line of `rest` when it is deeper than `indent`, else ""."""
    for line in rest:
        if _is_comment_or_blank(line):
            continue
        return line.strip() if _indent(line) > indent else ""
    return ""


def _mapping(lines: list[str], indent: int) -> dict[str, str]:
    out: dict[str, str] = {}
    for index, line in enumerate(lines):
        if _is_comment_or_blank(line) or _indent(line) != indent:
            continue
        name, _, value = line.strip().partition(":")
        out[name] = SourceStr(_scalar(value), value.strip(), _nested_line(lines[index + 1:], indent))
    return out


@dataclass
class Workflow:
    name: str
    lines: list[str]

    @classmethod
    def load(cls, name: str) -> Workflow:
        return cls(name, (WORKFLOWS / name).read_text(encoding="utf-8").splitlines())

    def top(self, key: str) -> list[str]:
        out: list[str] = []
        inside = False
        for line in self.lines:
            if line and not line[0].isspace() and not line.startswith("#"):
                inside = line.startswith(key + ":")
                if inside and line[len(key) + 1:].strip():
                    out.append("  " + line[len(key) + 1:].strip())
                continue
            if inside:
                out.append(line)
        return out

    def events(self) -> dict[str, list[str]]:
        events: dict[str, list[str]] = {}
        current = ""
        for line in self.top("on"):
            if _is_comment_or_blank(line):
                continue
            if _indent(line) == 2:
                current = line.strip().split(":", 1)[0]
                events[current] = []
            elif current:
                events[current].append(line)
        return events

    def branches(self, event: str) -> tuple[str, ...]:
        body = self.events().get(event)
        if body is None:
            return ()
        for index, line in enumerate(body):
            if _indent(line) == 4 and line.strip().startswith("branches:"):
                rest = line.strip()[len("branches:"):].strip()
                if rest:
                    return _flow_list(rest)
                items = []
                for item in body[index + 1:]:
                    if _indent(item) <= 4:
                        break
                    items.append(_scalar(item.strip()[2:]))
                return tuple(items)
        return ()

    def env(self) -> dict[str, str]:
        return _mapping(self.top("env"), 2)

    def jobs(self) -> dict[str, Job]:
        jobs: dict[str, list[str]] = {}
        current = ""
        for line in self.top("jobs"):
            if _is_comment_or_blank(line) and not current:
                continue
            if _indent(line) == 2 and not _is_comment_or_blank(line):
                current = line.strip().rstrip(":")
                jobs[current] = []
            elif current:
                jobs[current].append(line)
        return {job_id: Job(job_id, body) for job_id, body in jobs.items()}


CONTINUATION_RE = re.compile(r"\\\n\s*")
BLANKS_RE = re.compile(r"[ \t]+")


def _flat(text: str) -> str:
    """Join shell line continuations and squeeze blanks, so a command split over lines matches."""
    return BLANKS_RE.sub(" ", CONTINUATION_RE.sub(" ", text))


# #9737 (D2): an env value is compared by the value it takes on a leg, not by its text. A plain
# literal is itself; `${{ matrix.<name> || '<literal>' }}` is the leg's matrix value, or the
# literal when the leg does not set it. Every other expression form fails closed, naming the form.
EXPRESSION_OPEN = "${{"
MATRIX_OR_LITERAL_RE = re.compile(
    r"^\$\{\{\s*matrix\.([A-Za-z_][A-Za-z0-9_-]*)\s*\|\|\s*'([^']*)'\s*\}\}$")


class QuotedStr(str):
    """A matrix value written in quotes: YAML types it as a string whatever its spelling."""


# YAML 1.2 core schema (https://yaml.org/spec/1.2.2/#103-core-schema) spellings of a non-string.
YAML_NULL_RE = re.compile(r"^(?:~|null|Null|NULL)$")
YAML_BOOL_RE = re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$")
YAML_INT_RE = re.compile(r"^(?:[-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+)$")
YAML_FLOAT_RE = re.compile(
    r"^(?:[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?|[-+]?\.(?:inf|Inf|INF)"
    r"|\.(?:nan|NaN|NAN))$")
CANONICAL_INT_RE = re.compile(r"^-?[1-9][0-9]*$")


def _yaml_typed_form(text: str) -> str:
    """The YAML form an unquoted scalar takes when it is not a string, or "" when it is text or a
    canonical non-zero integer (rendered back as the same text)."""
    if CANONICAL_INT_RE.match(text):
        return ""
    for form, pattern in (("null", YAML_NULL_RE), ("boolean", YAML_BOOL_RE),
                          ("integer", YAML_INT_RE), ("float", YAML_FLOAT_RE)):
        if pattern.match(text):
            return form
    return ""


# #9745 r1 (L2): ONE strict reader for every matrix leg value and env value. A value is decoded to
# the exact string the runner uses, or the reader raises UnreadForm naming where it is and which
# form it did not read. There is no default and no raw-text fallback: the forms below are a closed
# list, and the refusal is the `else`.
UNREAD_FLOW_MAPPING = "flow mapping"
UNREAD_FLOW_SEQUENCE = "flow sequence"
UNREAD_BLOCK_SCALAR = "block scalar"
UNREAD_ALIAS = "alias"
UNREAD_ANCHOR = "anchor"
UNREAD_TAG = "tag"
UNREAD_EXPRESSION = "expression"
UNREAD_AFTER_QUOTE = "text after the closing quote"
UNREAD_UNTERMINATED = "unterminated quote"
UNREAD_ESCAPE = "escape in a double-quoted scalar"
UNREAD_COLON = "colon in a plain scalar"
UNREAD_RESERVED = "reserved indicator"
UNREAD_FLOW_INDICATOR = "flow indicator at the start of a plain scalar"
UNREAD_BLOCK_INDICATOR = "block collection indicator"
UNREAD_CONTROL = "control character"
UNREAD_NESTED = "nested or continued value"
UNREAD_INDENT = "mis-indented line"
UNREAD_DUPLICATE = "duplicate key"
UNREAD_LINE = "line that is not key: value with a plain identifier key"
UNREAD_BARE_DASH = "list entry that does not start with a key on the dash line"
UNREAD_AXIS = "matrix axis"
UNREAD_STRATEGY_BLOCK = "strategy is not a block mapping"
UNREAD_STRATEGY_KEY = "strategy key other than fail-fast, max-parallel and matrix"
UNREAD_MATRIX_BLOCK = "matrix is not a block mapping"
UNREAD_INCLUDE_BLOCK = "include is not a block list"
UNREAD_UNQUOTED_FORM = "unquoted YAML {form}"

PLAIN_FIRST_CHAR_REASONS = {
    "{": UNREAD_FLOW_MAPPING, "[": UNREAD_FLOW_SEQUENCE, ">": UNREAD_BLOCK_SCALAR,
    "|": UNREAD_BLOCK_SCALAR, "*": UNREAD_ALIAS, "&": UNREAD_ANCHOR, "!": UNREAD_TAG,
    "@": UNREAD_RESERVED, "`": UNREAD_RESERVED, "%": UNREAD_RESERVED,
    ",": UNREAD_FLOW_INDICATOR, "]": UNREAD_FLOW_INDICATOR, "}": UNREAD_FLOW_INDICATOR,
}
CONTROL_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
COMMENT_TAIL_RE = re.compile(r"^\s+#")
PLAIN_COMMENT_RE = re.compile(r"\s#")
PLAIN_COLON_RE = re.compile(r":(?:\s|$)")
BLOCK_INDICATOR_RE = re.compile(r"^[-?](?:\s|$)")
SINGLE_QUOTE, DOUBLE_QUOTE, BACKSLASH = "'", '"', "\\"


class UnreadForm(AssertionError):
    """A YAML form this reader does not model: it names `where`, the form (`reason`) and the text."""

    def __init__(self, where: str, reason: str, text: str) -> None:
        super().__init__(f"{where}: unread YAML form, {reason}: {text!r}")
        self.reason = reason


def _scan_quoted(text: str, where: str) -> tuple[str, str]:
    """(the unescaped body, the text after the closing quote) of a fully quoted scalar. Single
    quotes unescape `''`; a double-quoted scalar with a backslash escape is refused."""
    quote = text[0]
    out: list[str] = []
    index = 1
    while index < len(text):
        char = text[index]
        if quote == DOUBLE_QUOTE and char == BACKSLASH:
            raise UnreadForm(where, UNREAD_ESCAPE, text)
        if char == quote:
            if quote == SINGLE_QUOTE and text[index + 1:index + 2] == SINGLE_QUOTE:
                out.append(SINGLE_QUOTE)
                index += 2
                continue
            return "".join(out), text[index + 1:]
        out.append(char)
        index += 1
    raise UnreadForm(where, UNREAD_UNTERMINATED, text)


def _decode_scalar(raw: str, where: str, allow_expression: bool) -> str:
    """The string a runner reads from the text after `key:`: a QuotedStr for a quoted scalar, a plain
    str for a plain scalar, "" for null. Every other form raises UnreadForm (never a default)."""
    text = raw.strip()
    if CONTROL_RE.search(text):
        raise UnreadForm(where, UNREAD_CONTROL, text)
    if not text or text.startswith("#"):
        return ""
    if text[0] in (SINGLE_QUOTE, DOUBLE_QUOTE):
        body, tail = _scan_quoted(text, where)
        if tail and not COMMENT_TAIL_RE.match(tail):
            raise UnreadForm(where, UNREAD_AFTER_QUOTE, text)
        if not allow_expression and EXPRESSION_OPEN in body:
            raise UnreadForm(where, UNREAD_EXPRESSION, text)
        return QuotedStr(body)
    reason = PLAIN_FIRST_CHAR_REASONS.get(text[0])
    if reason is None and BLOCK_INDICATOR_RE.match(text):
        reason = UNREAD_BLOCK_INDICATOR
    if reason is not None:
        raise UnreadForm(where, reason, text)
    plain = PLAIN_COMMENT_RE.split(text, 1)[0].rstrip()
    if EXPRESSION_OPEN in plain:
        if not allow_expression:
            raise UnreadForm(where, UNREAD_EXPRESSION, text)
    elif PLAIN_COLON_RE.search(plain):
        raise UnreadForm(where, UNREAD_COLON, text)
    return plain


def _effective_env_value(name: str, raw: str, leg: dict[str, object]) -> str:
    """The value env var `name` takes on one leg; an expression form other than one fails. A value
    read from a workflow (SourceStr) is decoded by the strict reader first (#9745 r1)."""
    if isinstance(raw, SourceStr):
        if raw.nested:
            raise UnreadForm(name, UNREAD_NESTED, raw.nested)
        decoded = _decode_scalar(raw.source, name, True)
        if not isinstance(decoded, QuotedStr):
            form = _yaml_typed_form(decoded)
            if form and decoded != "0":
                raise UnreadForm(name, UNREAD_UNQUOTED_FORM.format(form=form), raw.source.strip())
        raw = str(decoded)
    if EXPRESSION_OPEN not in raw:
        return raw
    match = MATRIX_OR_LITERAL_RE.match(raw)
    if not match:
        raise AssertionError(f"{name}: unrecognised expression form in an env value: {raw!r}")
    field_name, literal = match.groups()
    value = leg.get(field_name)
    if value is None or value == "":
        return literal
    # `||` takes the literal for a falsy matrix value (false, 0, ''). A quoted value is a string
    # and is taken as written (QuotedStr, set by _matrix_include). An unquoted one is typed by
    # YAML: a bare 0 is falsy and a bare 1.0 renders as 1, so only a canonical non-zero integer is
    # read as its text; every other bare null, boolean or number spelling is refused (#9745).
    if isinstance(value, QuotedStr):
        return str(value)
    if isinstance(value, bool) or str(value).strip() in ("0", "0.0", "-0"):
        raise AssertionError(f"{name}: matrix.{field_name} = {value!r} is truthy when quoted and "
                             f"falsy when not, and this parser drops the quotes: {raw!r}")
    form = _yaml_typed_form(str(value))
    if form:
        raise AssertionError(f"{name}: matrix.{field_name} = {value!r} is an unquoted YAML "
                             f"{form}, which the runner reads as a typed value, not as this "
                             f"text: {raw!r}")
    return str(value)


def _effective_key_env(env: dict[str, str], leg: dict[str, object]) -> dict[str, str]:
    """The CARGO*/RUST*/CC*/... env rust-cache hashes into the key, as one leg sees it."""
    out: dict[str, str] = {}
    for name, raw in env.items():
        if name.startswith(KEY_ENV_PREFIXES):
            value = _effective_env_value(name, raw, leg)
            if value != "":
                out[name] = value
    return out


def _leg_id(leg: dict[str, object]) -> str:
    """A leg's name: the first key of its matrix entry (`leg`, `target`), or "" without a matrix."""
    if not leg:
        return ""
    first = next(iter(leg))
    return f"{first}={leg[first]}"


def _cache_index(steps: list[Step]) -> int:
    hits = [i for i, step in enumerate(steps) if step.uses_name() == RUST_CACHE]
    if len(hits) != 1:
        raise AssertionError(f"expected exactly one rust-cache step, found {len(hits)}")
    return hits[0]


def _all_workflow_names() -> list[str]:
    return sorted(p.name for p in WORKFLOWS.iterdir() if p.suffix in (".yml", ".yaml"))


TEST_RUN_RE = re.compile(
    r"cargo (?:test|llvm-cov|nextest|bench|clippy|check|fmt|build|audit)\b|-m unittest|pytest"
    r"|scripts/[\w./-]+\.(?:sh|py)\b")


def _test_step_labels(job: Job) -> tuple[str, ...]:
    return tuple(s.label() for s in job.steps() if TEST_RUN_RE.search(s.run()))


# #9745 r1 (L3): the checks below walk `_reachable_jobs`. The remaining `wf.jobs()` uses in this
# module are kept on purpose, each commented where it stands: lookups by an explicit job id from
# a hand table (PAIRS, JOBS, TEST_STEPS, CI_GATE_JOB, the warm workflow), where a missing id is a
# KeyError and a called workflow is not meant; and the whole-file V-4 key walk, which visits
# every workflow file and so every called workflow once under its own name.
def _rust_cache_site_counts() -> tuple[dict[str, dict[str, int]], list[str]]:
    """({workflow: {job: rust-cache step count}}, problems) over the PR-startable workflows
    (#9747 r1: L3)."""
    found: dict[str, dict[str, int]] = {}
    problems: list[str] = []
    for name in _all_workflow_names():
        wf = Workflow.load(name)
        if not PR_EVENTS & set(wf.events()):
            continue
        jobs, unread = _reachable_jobs(wf)
        problems.extend(f"{name}: {problem}" for problem in unread)
        for job_id, _job_wf, job in jobs:
            count = sum(1 for s in job.steps() if s.uses_name() == RUST_CACHE)
            if count:
                found.setdefault(name, {})[job_id] = count
    return found, problems


def _rust_cache_step_failures(names: list[str]) -> list[str]:
    """Every rust-cache step of `names` that is not the pinned sha, push-only save, no on-failure."""
    failures: list[str] = []
    for name in names:
        jobs, unread = _reachable_jobs(Workflow.load(name))
        failures.extend(f"{name}: {problem}" for problem in unread)
        for job_id, _job_wf, job in jobs:
            for step in job.steps():
                if step.uses_name() != RUST_CACHE:
                    continue
                sha = step.keys["uses"].partition("@")[2]
                if sha != RUST_CACHE_SHA:
                    failures.append(f"{name}:{job_id}: rust-cache sha {sha!r} is not the pinned "
                                    f"{RUST_CACHE_SHA}")
                save_if = step.mapping("with").get("save-if")
                if save_if != SAVE_IF_PUSH:
                    failures.append(f"{name}:{job_id}: save-if is {save_if!r}, not the push gate")
                if "cache-on-failure" in step.mapping("with"):
                    failures.append(f"{name}:{job_id}: cache-on-failure is set")
    return failures


def _pr_cache_action_failures() -> list[str]:
    """Every actions/cache step, and every unguarded cache save, of a PR-startable workflow."""
    failures: list[str] = []
    for name in _all_workflow_names():
        wf = Workflow.load(name)
        if not PR_EVENTS & set(wf.events()):
            continue
        jobs, unread = _reachable_jobs(wf)
        failures.extend(f"{name}: {problem}" for problem in unread)
        for job_id, _job_wf, job in jobs:
            for step in job.steps():
                where = f"{name}:{job_id}: {step.label()}"
                if step.uses_name() == CACHE_COMBINED:
                    failures.append(f"{where}: actions/cache saves in its post step on every event")
                if step.uses_name() == CACHE_SAVE and not step.keys.get("if", "").startswith(PUSH_GATE):
                    failures.append(f"{where}: cache save is not gated on a push: "
                                    f"{step.keys.get('if')!r}")
    return failures


def _shared_key_owners(names: list[str]) -> dict[str, list[str]]:
    """{shared-key: [workflow:job of every rust-cache step that sets it]} over `names`."""
    shared_keys: dict[str, list[str]] = {}
    for name in names:
        jobs, unread = _reachable_jobs(Workflow.load(name))
        if unread:
            raise AssertionError("\n".join(f"{name}: {problem}" for problem in unread))
        for job_id, _job_wf, job in jobs:
            for step in job.steps():
                if step.uses_name() == RUST_CACHE and "shared-key" in step.mapping("with"):
                    shared_keys.setdefault(step.mapping("with")["shared-key"], []).append(
                        f"{name}:{job_id}")
    return shared_keys


class RustCacheSaveScope9681(unittest.TestCase):
    """Every cache write in a PR-startable workflow comes from a push run (#9681)."""

    def test_rust_cache_sites_match_the_hand_table(self) -> None:
        counts, problems = _rust_cache_site_counts()
        self.assertEqual(problems, [])
        self.assertEqual(counts, RUST_CACHE_SITES)

    def test_every_rust_cache_step_saves_only_on_push(self) -> None:
        self.assertEqual(_rust_cache_step_failures([*RUST_CACHE_SITES, WARM]), [])

    def test_no_pr_run_saves_an_actions_cache(self) -> None:
        self.assertEqual(_pr_cache_action_failures(), [])

    def test_hf_model_cache_restores_everywhere_and_saves_on_push(self) -> None:
        for (name, job_id), (restore_name, save_name) in HF_CACHE_SITES.items():
            steps = Workflow.load(name).jobs()[job_id].steps()
            by_label = {s.label(): s for s in steps}
            with self.subTest(workflow=name, job=job_id):
                restore, save = by_label[restore_name], by_label[save_name]
                self.assertEqual(restore.uses_name(), CACHE_RESTORE)
                self.assertEqual(save.uses_name(), CACHE_SAVE)
                self.assertNotIn("if", restore.keys)
                rid = restore.keys["id"]
                self.assertEqual(save.keys["if"],
                                 f"{PUSH_GATE} && steps.{rid}.outputs.cache-hit != 'true'")
                self.assertEqual(restore.mapping("with")["path"], save.mapping("with")["path"])
                self.assertEqual(restore.mapping("with")["key"], save.mapping("with")["key"])
                self.assertLess(steps.index(restore), steps.index(save))

    def test_push_branches_are_the_hand_table(self) -> None:
        for name, branches in PUSH_BRANCHES.items():
            with self.subTest(workflow=name):
                self.assertEqual(Workflow.load(name).branches("push"), branches)

    def test_warm_workflow_is_push_only_hosted_and_least_privilege(self) -> None:
        wf = Workflow.load(WARM)
        self.assertEqual(list(wf.events()), ["push"])
        self.assertEqual([line.strip() for line in wf.events()["push"]
                          if not _is_comment_or_blank(line)], ['branches: ["chain/**"]'])
        self.assertIn("permissions:\n  contents: read\n", "\n".join(wf.lines) + "\n")
        self.assertEqual([line.strip() for line in wf.top("permissions")
                          if not _is_comment_or_blank(line)], ["contents: read"])
        concurrency = _mapping(wf.top("concurrency"), 2)
        self.assertEqual(concurrency.get("group"), "rust-cache-warm-${{ github.ref_name }}")
        self.assertEqual(concurrency.get("cancel-in-progress"), "false")
        self.assertNotIn("pull_request", "\n".join(wf.lines))
        # wf.jobs() walk kept (#9745 r1 L3): the warm workflow is push-only and its jobs are
        # checked by their own ids; a job-level `uses:` there would fail `runs-on` below.
        for job_id, job in wf.jobs().items():
            with self.subTest(job=job_id):
                self.assertEqual(job.scalar("runs-on"), "ubuntu-latest")
                self.assertIsNone(FED_LABEL_RE.search(job.scalar("runs-on") or "matrix"))
                self.assertEqual(job.block("strategy"), [])
                self.assertEqual(job.block("services"), [])
                self.assertEqual(job.block("permissions"), [])
                self.assertIsNone(job.scalar("needs"))
                for step in job.steps():
                    if step.uses_name() == "actions/checkout":
                        self.assertEqual(step.mapping("with").get("persist-credentials"), "false")
                    self.assertNotIn("secrets.", "\n".join(step.lines))

    def test_job_ids_and_names_are_the_hand_table(self) -> None:
        required = {line.strip() for line in REQUIRED_CONTEXTS.read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.startswith("#")}
        for name, jobs in JOBS.items():
            with self.subTest(workflow=name):
                actual = {job_id: job.scalar("name") for job_id, job in Workflow.load(name).jobs().items()}
                self.assertEqual(actual, jobs)
        for job_name in JOBS[WARM].values():
            self.assertNotIn(job_name, required)

    def test_ci_gate_needs_every_gated_job(self) -> None:
        gate = Workflow.load("ci.yml").jobs()["ci-gate"]
        needs = gate.scalar("needs") or ""
        if needs:
            listed = _flow_list(needs)
        else:
            listed = tuple(_scalar(line.strip()[2:]) for line in gate.block("needs")
                           if line.strip().startswith("- "))
        self.assertEqual(listed, CI_GATE_NEEDS)

    def test_test_steps_are_unchanged(self) -> None:
        for name, jobs in TEST_STEPS.items():
            wf_jobs = Workflow.load(name).jobs()
            for job_id, labels in jobs.items():
                with self.subTest(workflow=name, job=job_id):
                    self.assertEqual(_test_step_labels(wf_jobs[job_id]), labels)
        self.assertEqual(set(TEST_STEPS), set(JOBS) - {WARM})

    def test_warm_jobs_write_the_key_their_pr_jobs_restore(self) -> None:
        warm = Workflow.load(WARM)
        warm_jobs = warm.jobs()
        shared_keys = _shared_key_owners([*RUST_CACHE_SITES, WARM])
        for pr_name, pr_job_id, warm_job_id, shared_key in PAIRS:
            pr_wf = Workflow.load(pr_name)
            pr_job, warm_job = pr_wf.jobs()[pr_job_id], warm_jobs[warm_job_id]
            pr_steps, warm_steps = pr_job.steps(), warm_job.steps()
            pr_cache, warm_cache = _cache_index(pr_steps), _cache_index(warm_steps)
            with self.subTest(pair=warm_job_id, part="shared-key"):
                for step in (pr_steps[pr_cache], warm_steps[warm_cache]):
                    inputs = step.mapping("with")
                    self.assertEqual(inputs.get("shared-key"), shared_key)
                    for absent in ("key", "add-job-id-key",
                                   "add-rust-environment-hash-key", "env-vars", "workspaces"):
                        self.assertNotIn(absent, inputs)
                # prefix-key leads the restore key, so the PR job and its warm job carry the same.
                self.assertEqual(pr_steps[pr_cache].mapping("with").get("prefix-key"),
                                 warm_steps[warm_cache].mapping("with").get("prefix-key"))
                self.assertEqual(sorted(shared_keys[shared_key]),
                                 sorted([f"{pr_name}:{pr_job_id}", f"{WARM}:{warm_job_id}"]))
            # #9737: evaluated per hosted leg of the PR job (the warm job has no matrix).
            pr_env = {**pr_wf.env(), **pr_job.env()}
            warm_env = {**warm.env(), **warm_job.env()}
            legs = _hosted_legs(pr_job)
            with self.subTest(pair=warm_job_id, part="key-env-has-a-hosted-leg"):
                self.assertNotEqual(legs, [])
            for leg in legs:
                with self.subTest(pair=warm_job_id, part="key-env", leg=_leg_id(leg)):
                    self.assertEqual(_effective_key_env(warm_env, {}),
                                     _effective_key_env(pr_env, leg))
                    other = sorted(k for k in warm_env if not k.startswith(KEY_ENV_PREFIXES))
                    self.assertEqual([k for k in other if k not in pr_env], [])
                    self.assertEqual(
                        {k: _effective_env_value(k, warm_env[k], {}) for k in other},
                        {k: _effective_env_value(k, pr_env[k], leg) for k in other})
            with self.subTest(pair=warm_job_id, part="pre-cache-env-exports"):
                exporting = tuple(s.label() for s in pr_steps[:pr_cache] if "GITHUB_ENV" in s.run())
                self.assertEqual(exporting, PRE_CACHE_ENV_STEPS[(pr_name, pr_job_id)])
                self.assertEqual([s.label() for s in warm_steps[:warm_cache] if "GITHUB_ENV" in s.run()
                                  or "GITHUB_PATH" in s.run()], [])
            with self.subTest(pair=warm_job_id, part="mirrored-steps"):
                pr_by_label = {s.label(): s for s in pr_steps}
                warm_by_label = {s.label(): s for s in warm_steps}
                for label in MIRRORED_STEPS[(pr_name, pr_job_id)]:
                    pr_step, warm_step = pr_by_label[label], warm_by_label[label]
                    self.assertEqual(warm_step.keys.get("uses"), pr_step.keys.get("uses"), label)
                    self.assertEqual(warm_step.mapping("with"), pr_step.mapping("with"), label)
                    self.assertEqual(warm_step.mapping("env"), pr_step.mapping("env"), label)
                    self.assertEqual(warm_step.run(), pr_step.run(), label)
                    before_pr = pr_steps.index(pr_step) < pr_cache
                    self.assertEqual(warm_steps.index(warm_step) < warm_cache, before_pr, label)
            # #9770: the whole rust-cache step, each mirrored cargo step and the job-level keys.
            for leg in legs:
                with self.subTest(pair=warm_job_id, part="pair-mirror", leg=_leg_id(leg)):
                    self.assertEqual(
                        pair_mirror_problems(pr_wf, pr_job_id, warm, warm_job_id, leg), [])

    def test_taint_boundary_knows_the_split_cache_actions(self) -> None:
        sys.path.insert(0, str(REPO / "scripts" / "ci"))
        try:
            import taint_boundary as tb
        finally:
            sys.path.pop(0)
        for action in (CACHE_RESTORE, CACHE_SAVE):
            with self.subTest(action=action):
                self.assertIn(action, tb.KNOWN_ACTIONS)
                facts = tb.KNOWN_ACTIONS[action]
                self.assertFalse(facts.pr_code or facts.default_token or facts.script_input)


# --- vote V2-9681: the chain cache has one writer ------------------------------------------------

ON_KEY_RE = re.compile(r"""^(?:["']?on["']?|true)\s*:""")
# A rust-cache key input line: the one place a paired workflow may spell a chain key.
KEY_INPUT_RE = re.compile(r"^\s+(?:shared-key|prefix-key):\s*[A-Za-z0-9_.-]+\s*$")


def _numbered(path: Path) -> list[tuple[int, str]]:
    """(1-based line number, line) of every line that is not a comment or blank."""
    return [(n, line) for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
            if not _is_comment_or_blank(line)]


def _github_yaml_files() -> list[Path]:
    """Every workflow and composite action under .github (a shared key can hide in either)."""
    out = [p for p in WORKFLOWS.iterdir() if p.suffix in (".yml", ".yaml")]
    actions = REPO / ".github" / "actions"
    if actions.is_dir():
        out += [p for p in actions.rglob("*") if p.suffix in (".yml", ".yaml")]
    return sorted(out)


def _triggers(wf: Workflow) -> dict[str, list[str]]:
    """Trigger name -> body lines. An `on:` form this parser cannot read is an assertion, so an
    unreadable trigger never passes as 'no push'."""
    hits = [(n, line) for n, line in enumerate(wf.lines, 1) if ON_KEY_RE.match(line)]
    if len(hits) != 1 or not hits[0][1].startswith("on:"):
        raise AssertionError(f"{wf.name}: expected one plain top-level `on:` key, found "
                             f"{[f'{n}: {line}' for n, line in hits]}")
    inline = hits[0][1][len("on:"):].strip()
    if inline and not inline.startswith("#"):
        return {event: [] for event in _flow_list(inline)}
    return wf.events()


def _filter_list(body: list[str], key: str) -> tuple[str, ...] | None:
    for index, line in enumerate(body):
        if _indent(line) == 4 and line.strip().startswith(key + ":"):
            rest = line.strip()[len(key) + 1:].strip()
            if rest and not rest.startswith("#"):
                return _flow_list(rest)
            items = []
            for item in body[index + 1:]:
                if _is_comment_or_blank(item):
                    continue
                if _indent(item) <= 4:
                    break
                items.append(_scalar(item.strip()[2:]) if item.strip().startswith("- ")
                             else item.strip())
            return tuple(items)
    return None


def _glob_re(pattern: str) -> re.Pattern[str]:
    """GitHub branch-filter glob with only `*` (no `/`) and `**` (anything). A run of two or more
    stars is one `.*`, so no input builds a regex of nested unbounded repeats."""
    out = []
    for run in re.finditer(r"\*+|[^*]+", pattern):
        part = run.group(0)
        if part.startswith("*"):
            if not out or out[-1] not in (".*", "[^/]*"):
                out.append(".*" if len(part) > 1 else "[^/]*")
            elif len(part) > 1:
                out[-1] = ".*"
        else:
            out.append(re.escape(part))
    return re.compile("".join(out) + r"\Z")


def _pattern_reaches_chain(pattern: str) -> bool:
    """Whether a push.branches pattern can match a chain ref. A literal ref under `chain/` does;
    a `*`/`**` glob is matched against sample chain refs; a pattern with a GitHub-only operator
    (?, +, [], !) is judged conservatively on its literal head (reaches when that head is
    compatible with `chain/`)."""
    literal = ""
    for char in pattern:
        if char in GLOB_CHARS:
            break
        literal += char
    if literal.startswith(CHAIN_PREFIX):
        return True
    if literal == pattern:
        return False
    if GLOB_CHARS & set(pattern) - {"*"}:
        return CHAIN_PREFIX.startswith(literal)
    return any(_glob_re(pattern).match(ref) for ref in CHAIN_SAMPLE_REFS)


def _push_reaches_chain(wf: Workflow) -> str | None:
    """The reason a push to a chain ref starts this workflow, or None."""
    body = _triggers(wf).get("push")
    if body is None:
        return None
    branches = _filter_list(body, "branches")
    ignored = _filter_list(body, "branches-ignore")
    if branches is not None:
        hits = [p for p in branches if not p.startswith("!") and _pattern_reaches_chain(p)]
        return f"push.branches {hits}" if hits else None
    if ignored is not None:
        if any(p in ("**", "chain/**") for p in ignored):
            return None
        return f"push.branches-ignore {list(ignored)} does not exclude chain/**"
    if _filter_list(body, "tags") is not None or _filter_list(body, "tags-ignore") is not None:
        return None
    return "push has no branch filter, so every branch push starts it"


def _line_no(wf: Workflow, needle: str) -> int:
    in_on = False
    for n, line in enumerate(wf.lines, 1):
        if line.startswith("on:"):
            in_on = True
        elif line and not line[0].isspace() and not line.startswith("#"):
            in_on = False
        if in_on and needle in line:
            return n
    return 0


def _job_line(name: str, job_id: str, needle: str) -> int:
    """The line number of the first `needle` inside job `job_id` of workflow `name`, else 0."""
    inside = False
    for n, line in enumerate((WORKFLOWS / name).read_text(encoding="utf-8").splitlines(), 1):
        if _indent(line) == 2 and not _is_comment_or_blank(line):
            inside = line.strip().rstrip(":") == job_id
        elif inside and needle in line and not _is_comment_or_blank(line):
            return n
    return 0


def _header(path: Path) -> str:
    """The leading comment block, comment markers dropped and blanks squeezed."""
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        if not line.startswith("#"):
            break
        out.append(line[1:].strip())
    return " ".join(" ".join(out).split())


def _cache_step_inputs(name: str, job_id: str) -> tuple[Step, dict[str, str]]:
    steps = Workflow.load(name).jobs()[job_id].steps()
    step = steps[_cache_index(steps)]
    return step, step.mapping("with")


class ChainCacheSoleWriter9681(unittest.TestCase):
    """Vote V2-9681 conditions V-2 to V-11: rust-cache-warm.yml is the chain cache's only writer."""

    def test_v2_warm_header_cites_the_push_overlap_precedents(self) -> None:
        header = _header(WORKFLOWS / WARM)
        for phrase in V2_HEADER_PHRASES:
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, header,
                              f"{WARM}: header lacks {phrase!r} (V-2: cite #2506/#2523/#2508 and "
                              f"say why this chain/** push trigger is the one sanctioned exception)")

    def test_v3_only_the_warm_workflow_runs_on_a_chain_push(self) -> None:
        reaching: dict[str, str] = {}
        for name in _all_workflow_names():
            wf = Workflow.load(name)
            reason = _push_reaches_chain(wf)
            if reason is not None:
                reaching[name] = reason
                if name != WARM:
                    self.fail(f"{name}:{_line_no(wf, 'push')}: {reason}; only {WARM} may run on "
                              f"a chain/** push (V-3)")
        self.assertEqual(set(reaching), {WARM}, f"chain/** push workflows: {reaching}")

    def test_v3_no_release_artefact_workflow_runs_on_a_chain_push(self) -> None:
        for name in _all_workflow_names():
            wf = Workflow.load(name)
            if _push_reaches_chain(wf) is None:
                continue
            for n, line in _numbered(WORKFLOWS / name):
                with self.subTest(workflow=name, line=n):
                    self.assertIsNone(RELEASE_ARTEFACT_RE.search(line),
                                      f"{name}:{n}: {line.strip()} - a workflow that runs on a "
                                      f"chain/** push builds or publishes release artefacts (V-3)")

    def test_v4_shared_keys_and_generation_live_only_in_the_paired_workflows(self) -> None:
        _, warm_inputs = _cache_step_inputs(WARM, PAIRS[0][2])
        literals = (*SHARED_KEYS, warm_inputs.get("prefix-key", "<no prefix-key>"))
        for path in _github_yaml_files():
            holder = path.parent == WORKFLOWS and path.name in KEY_HOLDERS
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if holder and (_is_comment_or_blank(line) or KEY_INPUT_RE.match(line)):
                    # In a paired workflow the literal may sit only on a rust-cache key input,
                    # whose step the parse below ties to an owner job.
                    continue
                for literal in literals:
                    with self.subTest(file=path.name, line=n, literal=literal):
                        self.assertNotIn(literal, line,
                                         f"{path.relative_to(REPO)}:{n}: {line.strip()} - the chain "
                                         f"cache key {literal!r} is used outside the six paired "
                                         f"rust-cache steps (V-4)")
        for name in _all_workflow_names():
            # wf.jobs() walk kept (#9745 r1 L3): this visits EVERY workflow file, and a called
            # workflow is itself one of those files, so each rust-cache step is seen once, under
            # its own file name; `_reachable_jobs` would see it a second time through its caller.
            for job_id, job in Workflow.load(name).jobs().items():
                for step in job.steps():
                    if step.uses_name() != RUST_CACHE:
                        continue
                    inputs = step.mapping("with")
                    owner = any((name, job_id) in ((p[0], p[1]), (WARM, p[2])) for p in PAIRS)
                    owner = owner or any((name, job_id) in ((k[0], k[1]), (WARM, v[0]))
                                         for k, v in LEG_PAIRS.items())
                    with self.subTest(workflow=name, job=job_id):
                        for key in ("shared-key", "prefix-key"):
                            value = inputs.get(key, "")
                            where = f"{name}:{_job_line(name, job_id, f'{key}:')} (job {job_id})"
                            # #9732: the one dynamic shared-key, a hand-table exact match; it
                            # resolves per matrix leg to the literal of a LEG_PAIRS warm job.
                            if key == "shared-key" and value == LEG_SHARED_KEY_TEMPLATES.get(
                                    (name, job_id)):
                                continue
                            self.assertNotIn("${{", value, f"{where}: dynamic rust-cache {key} "
                                                           f"{value!r} could build a chain key "
                                                           f"(V-4)")
                            if not owner:
                                self.assertNotIn(value, literals,
                                                 f"{where}: rust-cache {key} {value!r} is a "
                                                 f"chain cache key (V-4)")

    def test_v5_every_warm_action_is_pinned_to_a_commit_sha(self) -> None:
        uses = [(n, m.group(1)) for n, line in _numbered(WORKFLOWS / WARM)
                if (m := USES_RE.match(line))]
        self.assertTrue(uses, f"{WARM}: no uses: line parsed")
        for n, ref in uses:
            with self.subTest(line=n):
                self.assertRegex(ref, PINNED_USES_RE,
                                 f"{WARM}:{n}: uses {ref} is not pinned to a 40-hex commit sha (V-5)")

    def test_v6_warm_triggers_and_no_artifact_token_or_secret(self) -> None:
        wf = Workflow.load(WARM)
        triggers = _triggers(wf)
        self.assertEqual(sorted(triggers), ["push"],
                         f"{WARM}:{_line_no(wf, ':')}: triggers {sorted(triggers)}; only push (V-6)")
        body = [line.strip() for line in triggers["push"] if not _is_comment_or_blank(line)]
        self.assertEqual(body, ['branches: ["chain/**"]'],
                         f"{WARM}: push filter {body}; exactly branches chain/** (V-6)")
        for n, line in _numbered(WORKFLOWS / WARM):
            with self.subTest(line=n):
                self.assertIsNone(WARM_FORBIDDEN_RE.search(line),
                                  f"{WARM}:{n}: {line.strip()} - upload-artifact, id-token or a "
                                  f"secrets reference in the chain cache writer (V-6)")

    def test_v7_one_prefix_key_generation_at_the_six_paired_steps(self) -> None:
        sites = {}
        pairs = [(a, b, c) for a, b, c, _ in PAIRS]
        pairs += [(k[0], k[1], v[0]) for k, v in LEG_PAIRS.items()]
        for pr_name, pr_job_id, warm_job_id in pairs:
            for name, job_id in ((pr_name, pr_job_id), (WARM, warm_job_id)):
                _, inputs = _cache_step_inputs(name, job_id)
                sites[f"{name}:{job_id}"] = inputs.get("prefix-key")
        self.assertEqual(len(sites), 6)
        values = set(sites.values())
        self.assertEqual(len(values), 1, f"prefix-key differs across the six paired cache steps: "
                                         f"{sites} (V-7)")
        (value,) = values
        self.assertIsNotNone(value, f"no prefix-key at the six paired cache steps: {sites} (V-7)")
        self.assertRegex(value, PREFIX_KEY_RE,
                         f"prefix-key {value!r} is not a chain-cache-g<N> generation (V-7)")

    def test_v8_check_cache_step_is_hosted_only(self) -> None:
        for pr_name, pr_job_id, _, _ in PAIRS:
            job = Workflow.load(pr_name).jobs()[pr_job_id]
            step, _ = _cache_step_inputs(pr_name, pr_job_id)
            with self.subTest(workflow=pr_name, job=pr_job_id):
                if pr_name == "ci.yml" or job.scalar("runs-on") != "ubuntu-latest":
                    self.assertIn(HOSTED_GUARD, step.keys.get("if", ""),
                                  f"{pr_name}:{pr_job_id}: rust-cache if {step.keys.get('if')!r} "
                                  f"lacks {HOSTED_GUARD} (V-8)")

    def test_v9_no_privileged_trigger_touches_a_cache(self) -> None:
        to_scan: list[tuple[str, str]] = []
        for name in _all_workflow_names():
            events = set(_triggers(Workflow.load(name)))
            if events & PRIVILEGED_EVENTS:
                to_scan.append((name, ",".join(sorted(events & PRIVILEGED_EVENTS))))
        seen: set[str] = set()
        while to_scan:
            name, why = to_scan.pop()
            if name in seen:
                continue
            seen.add(name)
            for n, line in _numbered(WORKFLOWS / name):
                with self.subTest(workflow=name, line=n):
                    self.assertIsNone(CACHE_USES_RE.match(line),
                                      f"{name}:{n}: {line.strip()} - a workflow started by {why} "
                                      f"uses a cache action (V-9)")
                called = USES_RE.match(line)
                if called and called.group(1).startswith("./.github/workflows/"):
                    to_scan.append((Path(called.group(1)).name, f"{why} via {name}"))

    def test_v10_no_warm_job_is_required_or_gated(self) -> None:
        warm_jobs = Workflow.load(WARM).jobs()
        identities = {job_id for job_id in warm_jobs} | {job.scalar("name") or "" for job in
                                                          warm_jobs.values()}
        required = {line.strip() for line in REQUIRED_CONTEXTS.read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.startswith("#")}
        gate = Workflow.load(CI_GATE_JOB[0]).jobs()[CI_GATE_JOB[1]]
        needs_raw = gate.scalar("needs") or ""
        needs = set(_flow_list(needs_raw)) if needs_raw else {
            _scalar(line.strip()[2:]) for line in gate.block("needs") if line.strip().startswith("- ")}
        protection = BRANCH_PROTECTION.read_text(encoding="utf-8") if BRANCH_PROTECTION.exists() else ""
        names = {job.scalar("name") or "" for job in warm_jobs.values()}
        for ident in sorted(identities):
            with self.subTest(job=ident):
                self.assertTrue(ident, f"{WARM}: a warm job has no name (V-10)")
                self.assertNotIn(ident, required, f"{REQUIRED_CONTEXTS.name}: warm job {ident!r} is a "
                                                  f"required context (V-10)")
                self.assertNotIn(ident, needs, f"{CI_GATE_JOB[0]}:{CI_GATE_JOB[1]}: needs warm job "
                                               f"{ident!r} (V-10)")
                if ident in names:
                    # Contexts are job names; a bare job id such as `coverage` is ordinary prose.
                    self.assertNotIn(ident, protection, f"{BRANCH_PROTECTION.name}: names warm job "
                                                        f"{ident!r} (V-10)")

    def test_v3_chain_push_classifier_table(self) -> None:
        """The scan's verdict for each push-filter shape a later edit could introduce."""
        reaching = ('branches: ["chain/**"]', 'branches: ["chain/*"]', 'branches: ["**"]',
                    'branches: ["*/**"]', 'branches: ["ch*/**"]', 'branches: ["c***"]',
                    'branches: ["chain/promo6-ssh-r2"]', 'branches: ["chai?/**"]',
                    'branches: ["[c]hain/**"]', 'branches: ["chain/**", "!chain/x"]',
                    "branches:\n      - main\n      - 'chain/**'",
                    'branches-ignore: ["main"]', None)
        quiet = ('branches: [main, develop, "release/**"]', 'branches: ["chainx/**"]',
                 'branches: ["*"]', 'branches: ["c*"]', 'branches: ["!chain/**"]',
                 'branches-ignore: ["chain/**"]',
                 'branches-ignore: ["**"]', 'tags: ["v*"]', 'tags-ignore: ["x"]')
        for body, expect in [(b, True) for b in reaching] + [(b, False) for b in quiet]:
            lines = ["on:", "  push:"] + ([] if body is None else
                                          [("    " + part if not part.startswith(" ") else part)
                                           for part in body.split("\n")])
            with self.subTest(body=body):
                got = _push_reaches_chain(Workflow("synthetic.yml", [*lines, "jobs: {}"]))
                self.assertEqual(got is not None, expect, f"push filter {body!r}: {got!r}")

    def test_v3_unreadable_on_form_fails_closed(self) -> None:
        for lines in (['"on":', "  push:"], ["true:", "  push:"], ["on:", "  push:", "on:"]):
            with self.subTest(lines=lines), self.assertRaisesRegex(AssertionError,
                                                                   "expected one plain top-level"):
                _triggers(Workflow("synthetic.yml", lines))
        self.assertEqual(sorted(_triggers(Workflow("s.yml", ["on: [push, pull_request]"]))),
                         ["pull_request", "push"])

    def test_v3_scanner_is_linear_on_a_large_filter(self) -> None:
        """100K branch patterns and a 100K-character pattern: the scan stays well under a second."""
        many = ["on:", "  push:", "    branches:"] + [f"      - rel/{i}" for i in range(100_000)]
        start = time.monotonic()
        self.assertIsNone(_push_reaches_chain(Workflow("big.yml", many)))
        self.assertFalse(_pattern_reaches_chain("x" * 100_000 + "*" * 100_000))
        self.assertFalse(_pattern_reaches_chain("*a" * 50_000 + "z"))
        self.assertTrue(_pattern_reaches_chain("*" * 100_000 + "/**"))
        self.assertLess(time.monotonic() - start, 5.0)

    def test_v11_kill_switch_and_revert_rule_are_stated(self) -> None:
        texts = {WARM: _header(WORKFLOWS / WARM),
                 CHANGELOG_9681.name: " ".join(CHANGELOG_9681.read_text(encoding="utf-8").split())}
        for where, text in texts.items():
            for phrase in V11_PHRASES:
                with self.subTest(file=where, phrase=phrase):
                    self.assertIn(phrase, text, f"{where}: lacks {phrase!r} (V-11: kill switch and "
                                                f"the generation bump on a build-affecting revert)")


# --- #9681 r1: one cargo command list, derived from both workflows ------------------------------
#
# Invariant: every cargo command a hosted PR leg runs whose output rust-cache keeps (target/
# builds and `cargo install` binaries in ~/.cargo/bin) is run by its warm job with the EXACT same
# command line, and the warm job runs no other cargo command. Both lists are read from the
# workflow files; only the shell lines a static read cannot resolve are named below, each with
# its reason, and a table row that no longer matches a workflow line is itself a failure.

REPO_SLUG = "alphaonedev/ai-memory-mcp"
# The values a step `if:` can read on a same-repository pull_request run of a hosted leg (chain
# PRs are same-repository; a fork PR never reaches the chain cache). Any other name fails closed.
HOSTED_PR_CONTEXT: dict[str, object] = {
    "needs.classify.outputs.cargo_skip": "false",
    "runner.environment": "github-hosted",
    "runner.os": "Linux",
    # #9821 (I5): the hosted leg is never skipped (the skip condition needs a self-hosted runner).
    "env.LEG_SKIP": "false",
    "github.event_name": "pull_request",
    "github.repository": REPO_SLUG,
    "github.event.pull_request.head.repo.full_name": REPO_SLUG,
}
# Cargo subcommands whose output rust-cache saves (target/, ~/.cargo/bin, ~/.cargo/registry).
PRODUCING_SUBCOMMANDS = frozenset({"build", "test", "install", "llvm-cov", "check", "clippy",
                                   "rustc", "doc", "bench", "nextest", "run", "fetch"})
# Cargo subcommands that leave nothing a cache keeps, each with its reason.
NON_PRODUCING_SUBCOMMANDS: dict[str, str] = {
    "clean": "removes target/ entries; a PR run saves no cache, so nothing it removes is kept",
    "audit": "reads the advisory database; `cargo audit --version` only probes the installed binary",
    "metadata": "prints the package graph",
    "fmt": "checks formatting; builds nothing",
}
# PR-leg cargo lines a static read cannot resolve (shell variables, or a second call over the
# same build): (workflow, job, exact line) -> (the warm command it needs, or None, reason).
RESOLVED_PR_COMMANDS: dict[tuple[str, str, str], tuple[str | None, str]] = {
    ("ci.yml", "check", 'cargo test --no-run "$@"'): (
        "cargo test --no-run",
        "run_tests / run_doc_tests prebuild: on the hosted sqlite leg FEAT and TAIL are empty, the "
        "full suite passes no argument and the impact path passes --lib / --test names, a subset "
        "of the same build"),
    ("ci.yml", "check", 'cargo test --no-fail-fast "$@"'): (
        "cargo test --no-run",
        "runs the binaries the prebuild line above it built, with the same arguments"),
    ("ci.yml", "check", 'cargo test --doc --no-fail-fast "$@"'): (
        "cargo test --no-run",
        "doctests link the library the prebuild built; rustdoc's doctest binaries are not in target/"),
    ("ci.yml", "check", 'cargo test --no-run "$@" "${sel[@]}"'): (
        None, "run_isolated_lane: enterprise-fed tier only, never the hosted sqlite leg"),
    ("ci.yml", "check", 'cargo test --no-run --message-format=json-render-diagnostics $FEAT "$@"'): (
        None, "run_sharded: enterprise-fed tier only, never the hosted sqlite leg"),
    ("coverage.yml", "per-module-thresholds",
     "cargo llvm-cov --no-clean --features sal,sal-postgres --lib --workspace --json --output-path "
     "coverage/current.json -- schema_init_postgres_embedding_dim_conversion --ignored "
     "--test-threads=1"): (
        "cargo llvm-cov --no-report --features sal,sal-postgres --lib --tests --workspace -- "
        "--test-threads=1",
        "report call: --no-clean reuses the first call's instrumented build, and --lib with the "
        "same features is a subset of --lib --tests"),
}
# Test-runner arguments (after `--`) a warm command may append: they reach the test binary, not
# the compiler, so the build is the PR command's build.
WARM_RUNNER_SUFFIX: dict[str, tuple[str, str]] = {
    "coverage": ("--exact __rust_cache_warm_no_such_test__",
                 "matches no test, so the instrumented binaries start and exit without Postgres"),
}

CARGO_WORD_RE = re.compile(r"(?<![\w$/.{-])cargo(?=[ \t])")
SHELL_STOP_CHARS = frozenset("();<>|&")
ENV_REF_RE = re.compile(r'"\$\{([A-Za-z_][A-Za-z0-9_]*)\}"|\$\{([A-Za-z_][A-Za-z0-9_]*)\}'
                        r'|"\$([A-Za-z_][A-Za-z0-9_]*)"|\$([A-Za-z_][A-Za-z0-9_]*)')
IF_TOKEN_RE = re.compile(r"\s*(\(|\)|&&|\|\||!=|==|!|,|'[^']*'|[A-Za-z_][\w.-]*|\d+)")
IF_FUNCTIONS = frozenset({"always", "success", "contains"})


def _inside_quotes(line: str, pos: int) -> bool:
    quote = ""
    escaped = False
    for char in line[:pos]:
        if escaped:
            escaped = False
        elif char == "\\" and quote != "'":
            escaped = True
        elif quote:
            quote = "" if char == quote else quote
        elif char in "'\"":
            quote = char
    return bool(quote)


def _command_at(text: str) -> str:
    """The words of one cargo invocation, up to the first shell operator or redirect."""
    lexer = shlex.shlex(text, posix=False, punctuation_chars=True)
    lexer.whitespace_split = True
    words: list[str] = []
    for token in lexer:
        if token and set(token) <= SHELL_STOP_CHARS:
            if set(token) & set("<>") and words and words[-1].isdigit():
                words.pop()
            break
        words.append(token)
    return " ".join(words)


def _cargo_commands(text: str) -> list[str]:
    """Every cargo invocation in a run text (a `cargo` word outside quotes and comments)."""
    out: list[str] = []
    for line in _flat(text).splitlines():
        if line.lstrip().startswith("#"):
            continue
        for match in CARGO_WORD_RE.finditer(line):
            if not _inside_quotes(line, match.start()):
                out.append(_command_at(line[match.start():]))
    return out


def _expand(command: str, env: dict[str, str]) -> str:
    """Replace a reference to a variable the workflow sets (workflow, job or step env)."""
    def sub(match: re.Match[str]) -> str:
        name = next(group for group in match.groups() if group)
        return env[name] if name in env else match.group(0)
    return ENV_REF_RE.sub(sub, command)


def _subcommand(command: str) -> str:
    words = command.split()
    rest = words[2:] if len(words) > 1 and words[1].startswith("+") else words[1:]
    if not rest:
        raise AssertionError(f"cargo without a subcommand: {command!r}")
    return rest[0]


def _eval_if(expr: str, matrix: dict[str, object]) -> bool:
    """Evaluate a step `if:` for a hosted PR leg; an unknown name or form fails closed."""
    text = expr.strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2]
    tokens: list[str] = []
    pos = 0
    while pos < len(text):
        match = IF_TOKEN_RE.match(text, pos)
        if not match:
            if not text[pos:].strip():
                break
            raise AssertionError(f"unreadable if: {expr!r} at {text[pos:]!r}")
        tokens.append(match.group(1))
        pos = match.end()
    index = 0

    def peek() -> str:
        return tokens[index] if index < len(tokens) else ""

    def take(expected: str | None = None) -> str:
        nonlocal index
        token = peek()
        if not token or (expected is not None and token != expected):
            raise AssertionError(f"unreadable if: {expr!r} (wanted {expected!r}, got {token!r})")
        index += 1
        return token

    def atom() -> object:
        token = take()
        if token == "(":
            value = either()
            take(")")
            return value
        if token.startswith("'"):
            return token[1:-1]
        if token.isdigit():
            return int(token)
        if token in ("true", "false"):
            return token == "true"
        if peek() == "(":
            if token not in IF_FUNCTIONS:
                raise AssertionError(f"unknown function {token!r} in if: {expr!r}")
            take("(")
            args: list[object] = []
            while peek() != ")":
                args.append(either())
                if peek() == ",":
                    take(",")
            take(")")
            if token == "contains":
                return str(args[1]).lower() in str(args[0]).lower()
            return True
        if token.startswith("matrix."):
            return matrix.get(token[len("matrix."):])
        if token in HOSTED_PR_CONTEXT:
            return HOSTED_PR_CONTEXT[token]
        raise AssertionError(f"unknown name {token!r} in if: {expr!r}")

    def compare() -> object:
        left = atom()
        if peek() in ("==", "!="):
            op = take()
            right = atom()
            same = (str(left).lower() == str(right).lower()
                    if isinstance(left, str) and isinstance(right, str) else left == right)
            return same if op == "==" else not same
        return left

    def negation() -> object:
        if peek() == "!":
            take("!")
            return not negation()
        return compare()

    def both() -> object:
        value = negation()
        while peek() == "&&":
            take("&&")
            right = negation()
            value = value and right
        return value

    def either() -> object:
        value = both()
        while peek() == "||":
            take("||")
            right = both()
            value = value or right
        return value

    result = either()
    if index != len(tokens):
        raise AssertionError(f"unreadable if: {expr!r} (trailing {tokens[index:]!r})")
    return bool(result)


STRATEGY_KEYS = ("fail-fast", "max-parallel", "matrix")
MATRIX_INCLUDE_KEY = "include"
KEY_LINE_RE = re.compile(r"^([A-Za-z_][\w-]*):(?:[ \t]+(.*))?$")
DASH_LINE_RE = re.compile(r"^-( +)(\S.*)$")
PLAIN_BOOLEANS = {"true": True, "false": False}


def _inline_value(job: Job, key: str) -> str:
    """The text after `key:` on the job's own key line ("" when empty or only a comment)."""
    for line in job.lines:
        if _indent(line) == 4 and line.strip().startswith(key + ":"):
            rest = line.strip()[len(key) + 1:].strip()
            return "" if rest.startswith("#") else rest
    return ""


def _key_line(stripped: str, where: str) -> tuple[str, str]:
    match = KEY_LINE_RE.match(stripped)
    if not match:
        raise UnreadForm(where, UNREAD_LINE, stripped)
    return match.group(1), (match.group(2) or "").strip()


def _inline_text(value: str) -> str:
    """`value` unless it is empty or only a comment."""
    return "" if value.startswith("#") else value


def _key_sections(lines: list[str], indent: int, where: str
                  ) -> list[tuple[str, str, list[str], str]]:
    """Split block-mapping `lines` at `indent` into (key, inline text, deeper lines, key line)."""
    sections: list[tuple[str, str, list[str], str]] = []
    for line in lines:
        stripped = line.strip()
        if _indent(line) < indent:
            raise UnreadForm(where, UNREAD_INDENT, stripped)
        if _indent(line) > indent:
            sections[-1][2].append(line)
            continue
        key, value = _key_line(stripped, where)
        if any(key == seen[0] for seen in sections):
            raise UnreadForm(where, UNREAD_DUPLICATE, stripped)
        sections.append((key, _inline_text(value), [], stripped))
    return sections


def _include_entries(children: list[str], where: str) -> list[dict[str, object]]:
    """The legs of a block list of `key: scalar` mappings; any other line form is refused."""
    if not children[0].strip().startswith("-"):
        raise UnreadForm(where, UNREAD_INCLUDE_BLOCK, children[0].strip())
    entries: list[dict[str, object]] = []
    dash_indent = _indent(children[0])
    key_indent = -1
    last_key = ""
    for line in children:
        indent, stripped = _indent(line), line.strip()
        item_where = f"{where}[{len(entries) - 1}]"
        if indent == dash_indent:
            item_where = f"{where}[{len(entries)}]"
            if not stripped.startswith("-"):
                raise UnreadForm(f"{where}[{len(entries) - 1}]", UNREAD_INDENT, stripped)
            if stripped == "-":
                raise UnreadForm(item_where, UNREAD_BARE_DASH, stripped)
            dash = DASH_LINE_RE.match(stripped)
            if not dash:
                raise UnreadForm(item_where, UNREAD_LINE, stripped)
            content = dash.group(2)
            if content[0] in "{[":
                raise UnreadForm(item_where, PLAIN_FIRST_CHAR_REASONS[content[0]], content)
            key_indent = dash_indent + 1 + len(dash.group(1))
            entries.append({})
            last_key = ""
        elif indent == key_indent:
            content = stripped
        elif indent > key_indent and last_key:
            raise UnreadForm(f"{item_where}.{last_key}", UNREAD_NESTED, stripped)
        else:
            raise UnreadForm(item_where, UNREAD_INDENT, stripped)
        key, value = _key_line(content, item_where)
        if key in entries[-1]:
            raise UnreadForm(f"{item_where}.{key}", UNREAD_DUPLICATE, value)
        decoded = _decode_scalar(value, f"{item_where}.{key}", False)
        entries[-1][key] = decoded if isinstance(decoded, QuotedStr) \
            else PLAIN_BOOLEANS.get(decoded, decoded)
        last_key = key
    return entries


def _matrix_include(job: Job) -> list[dict[str, object]]:
    """The `strategy.matrix.include` legs of a job, as the runner reads them (#9745 r1: a closed
    list of forms; any other strategy, matrix, include or leg form raises UnreadForm)."""
    where = f"{job.job_id}: strategy"
    inline = _inline_value(job, "strategy")
    if inline:
        raise UnreadForm(where, UNREAD_STRATEGY_BLOCK, inline)
    lines = [line for line in job.block("strategy") if not _is_comment_or_blank(line)]
    if not lines:
        return []
    matrix: tuple[str, list[str]] | None = None
    for key, value, children, line in _key_sections(lines, _indent(lines[0]), where):
        if key not in STRATEGY_KEYS:
            raise UnreadForm(where, UNREAD_STRATEGY_KEY, line)
        if key == "matrix":
            matrix = (value, children)
        elif children:
            raise UnreadForm(f"{where}.{key}", UNREAD_NESTED, children[0].strip())
    if matrix is None:
        return []
    matrix_where = f"{where}.matrix"
    value, children = matrix
    if value or not children:
        raise UnreadForm(matrix_where, UNREAD_MATRIX_BLOCK, value)
    include: tuple[str, list[str]] | None = None
    for key, value, deeper, line in _key_sections(children, _indent(children[0]), matrix_where):
        if key != MATRIX_INCLUDE_KEY:
            raise UnreadForm(matrix_where, UNREAD_AXIS, line)
        include = (value, deeper)
    assert include is not None  # children is not empty and holds no key but include
    value, deeper = include
    if value or not deeper:
        raise UnreadForm(f"{matrix_where}.include", UNREAD_INCLUDE_BLOCK, value)
    return _include_entries(deeper, f"{matrix_where}.include")


def _hosted_legs(job: Job) -> list[dict[str, object]]:
    """The legs of a job that run on a GitHub-hosted runner, read from `runs-on` (#9681 r2: a
    runs-on form `_runs_on` does not read fails instead of counting as hosted)."""
    legs = _matrix_include(job) or [{}]
    return [leg for leg in legs if SELF_HOSTED not in _runs_on(job, leg)]


def _pr_leg_commands(name: str, job_id: str) -> tuple[list[str], list[str]]:
    """(the warm commands the hosted legs need, the problems) for one PR job."""
    wf = Workflow.load(name)
    job = wf.jobs()[job_id]
    needed: list[str] = []
    problems: list[str] = []
    seen: set[str] = set()
    legs = _hosted_legs(job)
    if not legs:
        problems.append(f"{name}:{job_id}: no hosted leg")
    for leg in legs:
        for step in job.steps():
            commands = _cargo_commands(step.run())
            if not commands or ("if" in step.keys and not _eval_if(step.keys["if"], leg)):
                continue
            env = {**wf.env(), **job.env(), **step.mapping("env")}
            for command in (_expand(c, env) for c in commands):
                seen.add(command)
                sub = _subcommand(command)
                if sub in NON_PRODUCING_SUBCOMMANDS:
                    continue
                if sub not in PRODUCING_SUBCOMMANDS:
                    problems.append(f"{step.label()}: unclassified cargo subcommand: {command}")
                    continue
                key = (name, job_id, command)
                if key in RESOLVED_PR_COMMANDS:
                    resolved = RESOLVED_PR_COMMANDS[key][0]
                    if resolved is not None:
                        needed.append(resolved)
                elif "$" in command:
                    problems.append(f"{step.label()}: unnamed dynamic cargo command: {command}")
                else:
                    needed.append(command)
    for row_name, row_job, row_command in RESOLVED_PR_COMMANDS:
        if (row_name, row_job) == (name, job_id) and row_command not in seen:
            problems.append(f"stale RESOLVED_PR_COMMANDS row (no such line): {row_command}")
    return sorted(set(needed)), problems


def _warm_commands(warm_job_id: str) -> tuple[list[str], list[str]]:
    """(the warm job's cargo commands, the problems): literal, cache-miss gated, after the cache."""
    wf = Workflow.load(WARM)
    job = wf.jobs()[warm_job_id]
    steps = job.steps()
    cache = _cache_index(steps)
    gate = f"steps.{steps[cache].keys.get('id', '')}.outputs.cache-hit != 'true'"
    commands: list[str] = []
    problems: list[str] = []
    suffix = WARM_RUNNER_SUFFIX.get(warm_job_id, ("", ""))[0]
    for index, step in enumerate(steps):
        env = {**wf.env(), **job.env(), **step.mapping("env")}
        for command in (_expand(c, env) for c in _cargo_commands(step.run())):
            if index < cache:
                problems.append(f"{step.label()}: cargo before the cache step: {command}")
            if step.keys.get("if") != gate:
                problems.append(f"{step.label()}: if is {step.keys.get('if')!r}, not {gate!r}")
            if "$" in command:
                problems.append(f"{step.label()}: warm command is not literal: {command}")
            if _subcommand(command) not in PRODUCING_SUBCOMMANDS:
                problems.append(f"{step.label()}: warm command builds nothing: {command}")
            if suffix and " -- " in command and command.endswith(" " + suffix):
                command = command[:-len(suffix) - 1]
            commands.append(command)
    return commands, problems


class WarmCommandList9681(unittest.TestCase):
    """#9681 r1 (C1, C2): the warm jobs and the hosted PR legs run one cargo command list."""

    def test_warm_job_runs_exactly_the_hosted_pr_leg_cargo_commands(self) -> None:
        for pr_name, pr_job_id, warm_job_id, _ in PAIRS:
            needed, pr_problems = _pr_leg_commands(pr_name, pr_job_id)
            warm, warm_problems = _warm_commands(warm_job_id)
            with self.subTest(pair=warm_job_id, part="pr-leg-commands-classified"):
                self.assertEqual(pr_problems, [])
            with self.subTest(pair=warm_job_id, part="warm-commands-literal-and-gated"):
                self.assertEqual(warm_problems, [])
            with self.subTest(pair=warm_job_id, part="no-command-twice"):
                self.assertEqual(len(warm), len(set(warm)), warm)
            with self.subTest(pair=warm_job_id, part="only-in-pr-leg"):
                self.assertEqual(sorted(set(needed) - set(warm)), [])
            with self.subTest(pair=warm_job_id, part="only-in-warm-job"):
                self.assertEqual(sorted(set(warm) - set(needed)), [])

    def test_command_reader_table(self) -> None:
        cases = {
            'cargo test --no-run "$@" || return "$?"': ['cargo test --no-run "$@"'],
            'if ! cargo audit --version 2>/dev/null | grep -Fqw -- "${V}"; then':
                ["cargo audit --version"],
            'echo "::notice::cargo test $FEAT"': [],
            'run_tests "full suite (cargo test)" $FEAT $TAIL': [],
            "# cargo build --release": [],
            'x "$T" --kill-after=60 "$S" cargo test --no-fail-fast "$@" || rc=$?':
                ['cargo test --no-fail-fast "$@"'],
            "cargo llvm-cov \\\n  --no-report \\\n  --lib": ["cargo llvm-cov --no-report --lib"],
            'cargo metadata --no-deps > "$meta"': ["cargo metadata --no-deps"],
            'echo "${CARGO_TARGET_DIR:?cargo target not set}"': [],
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(_cargo_commands(text), expected)
        self.assertEqual(_expand('cargo install x --version "${V}"', {"V": "0.22.2"}),
                         "cargo install x --version 0.22.2")
        self.assertEqual(_expand('cargo test "$@"', {"V": "1"}), 'cargo test "$@"')

    def test_if_evaluator_table_and_fail_closed(self) -> None:
        hosted = {"once": True, "runner": '["ubuntu-latest"]', "tier": "sqlite"}
        cases = {
            "needs.classify.outputs.cargo_skip != 'true' && matrix.once": True,
            "needs.classify.outputs.cargo_skip != 'true' && matrix.shared_target": False,
            "runner.environment == 'github-hosted'": True,
            "contains(matrix.runner, 'self-hosted')": False,
            "always() && matrix.tier == 'enterprise-fed'": False,
            "!matrix.shared_target && (github.event_name != 'pull_request' || true)": True,
            "${{ runner.os == 'linux' }}": True,
        }
        for expr, expected in cases.items():
            with self.subTest(expr=expr):
                self.assertIs(_eval_if(expr, hosted), expected)
        for bad in ("env.TEST_RESULT_LOG != ''", "hashFiles('x')", "matrix.a ==", "a ~ b",
                    "(always()"):
            with self.subTest(bad=bad), self.assertRaises(AssertionError):
                _eval_if(bad, hosted)

    def test_reader_is_linear_on_a_large_run_text(self) -> None:
        text = "\n".join(f'echo "cargo test {i}" && cargo build --bin b{i} || true'
                         for i in range(20_000))
        start = time.monotonic()
        commands = _cargo_commands(text)
        self.assertEqual(len(commands), 20_000)
        self.assertEqual(commands[-1], "cargo build --bin b19999")
        self.assertLess(time.monotonic() - start, 10.0)


# --- #9681 r1 S1: every cache writer a pull_request run can reach -------------------------------
#
# Each action a PR-startable workflow (and the warm workflow) uses is in exactly one table: a
# cache writer with the rule that keeps it from saving on a PR run, or an action that never
# writes the Actions cache, with the reason. An action in neither table fails, and so does a run
# text that drives the cache backend itself.

ACTIONS_LOCAL = REPO / ".github" / "actions"
# action -> (inputs that would make it save, the reason it saves nothing as configured).
CONFIG_GATED_WRITERS: dict[str, tuple[tuple[str, ...], str]] = {
    "actions/setup-python": (("cache", "cache-dependency-path"),
                             "v5 saves a pip/poetry cache only when `cache:` is set"),
    "actions/setup-node": (("cache", "cache-dependency-path", "package-manager-cache"),
                           "v4 saves a package-manager cache only when `cache:` is set"),
    "nttld/setup-ndk": (("local-cache",), "v1 saves the NDK to the Actions cache only with local-cache"),
    "docker/setup-buildx-action": (("version", "cache-binary"),
                                   "v3 caches the buildx binary only when it downloads a `version`"),
    "github/codeql-action/init": (("dependency-caching",),
                                  "v3 caches dependencies only when dependency-caching is set"),
}
# Writers whose save is decided by an event gate: action -> the input or key that must carry it.
EVENT_GATED_WRITERS = {
    RUST_CACHE: "save-if",
    CACHE_SAVE: "if",
    "docker/build-push-action": "cache-to",
}
NON_WRITER_ACTIONS: dict[str, str] = {
    "actions/checkout": "fetches the repository",
    CACHE_RESTORE: "restore half of the split cache action: it has no post step",
    "actions/upload-artifact": "uploads a run artifact, not an Actions cache entry",
    "dtolnay/rust-toolchain": "runs rustup; no cache input",
    "taiki-e/install-action": "downloads a pinned binary release; no cache input",
    "marocchino/sticky-pull-request-comment": "writes a PR comment",
    "reactivecircus/android-emulator-runner": "starts an emulator; no cache input",
    "github/codeql-action/analyze": "uploads SARIF",
    "docker://rhysd/actionlint:1.7.1": "a container step running actionlint",
    "./.github/actions/prune-runner-tmp": "local composite action; it uses no action and no cache "
                                          "(read by test_local_actions_hold_no_cache_writer)",
}
# Named exceptions: a cache writer that a pull_request run can reach today, with its tracker.
PR_CACHE_WRITER_EXCEPTIONS: dict[tuple[str, str, str], str] = {
    ("ci.yml", "dockerfile-validate", "Build Docker image (validation only)"):
        "#9711 (pre-existing at fd43a727): `cache-to: type=gha,mode=max` writes the buildx layer "
        "cache on pull_request and merge_group runs; a docker layer scope, never read by a "
        "rust-cache restore. The push gate lands with #9711, not in #9681.",
}
CACHE_BACKEND_TEXT_RE = re.compile(r"type=gha|SCCACHE_GHA|ACTIONS_CACHE_URL|ACTIONS_RESULTS_URL"
                                   r"|actions/cache|\bgh cache\b")


def _event_gated(step: Step, how: str) -> bool:
    """Whether a writer step saves only on push."""
    if how == "save-if":
        return step.mapping("with").get("save-if") == SAVE_IF_PUSH
    if how == "if":
        return step.keys.get("if", "").startswith(PUSH_GATE + " &&") or \
            step.keys.get("if", "") == PUSH_GATE
    value = step.mapping("with").get("cache-to")
    return value is None or value.startswith("${{ github.event_name == 'push' && ")


# --- #9681 r3 (#9747): a job-level `uses:` reaches the called workflow's jobs -----------------------
LOCAL_WORKFLOW_PREFIX = "./.github/workflows/"
CALL_DEPTH_MAX = 8


def _reachable_jobs(wf: Workflow, prefix: str = "", trail: tuple[str, ...] = ()
                    ) -> tuple[list[tuple[str, Workflow, Job]], list[str]]:
    """(every job a run of `wf` reaches as (job id, its workflow, job), the problems).

    A job of `wf` is itself. A job with a job-level `uses: ./.github/workflows/<x>.yml` stands for
    the jobs of that workflow, id `<caller job>/<called job>`, followed to CALL_DEPTH_MAX. Any
    other job-level `uses` (a remote reusable workflow, a `@ref`, a path outside the tree, a
    missing file, a cycle) is a problem: its jobs cannot be read, so the rule fails closed.

    The caller job's own `if:` is ignored: a call that a push-only or otherwise gated condition
    would skip still counts its inner jobs. That is the conservative side: it can over-report a
    site (a false problem a reader resolves by naming the site), never hide one (fail-closed)."""
    jobs: list[tuple[str, Workflow, Job]] = []
    problems: list[str] = []
    for job_id, job in wf.jobs().items():
        uses = job.scalar("uses")
        if uses is None:
            jobs.append((prefix + job_id, wf, job))
            continue
        called = uses[len(LOCAL_WORKFLOW_PREFIX):]
        where = f"{prefix}{job_id}"
        if (not uses.startswith(LOCAL_WORKFLOW_PREFIX) or "@" in called or "/" in called
                or not called.endswith((".yml", ".yaml"))):
            problems.append(f"{where}: job-level uses of a reusable workflow that is not a "
                            f"local {LOCAL_WORKFLOW_PREFIX}<name>.yml: {uses!r}")
        elif called in (*trail, wf.name):
            problems.append(f"{where}: reusable workflow call cycle: {uses!r}")
        elif len(trail) >= CALL_DEPTH_MAX:
            problems.append(f"{where}: reusable workflow call chain deeper than "
                            f"{CALL_DEPTH_MAX}: {uses!r}")
        elif called not in _all_workflow_names():
            problems.append(f"{where}: reusable workflow {uses!r} is not a file")
        else:
            inner, found = _reachable_jobs(Workflow.load(called), f"{where}/", (*trail, wf.name))
            jobs.extend(inner)
            problems.extend(found)
    return jobs, problems


def _pr_cache_writers() -> tuple[list[tuple[str, str, str]], list[str]]:
    """(writers a PR run reaches, problems) across every PR-startable workflow and the warm one."""
    reached: list[tuple[str, str, str]] = []
    problems: list[str] = []
    for name in _all_workflow_names():
        wf = Workflow.load(name)
        pr_run = bool(PR_EVENTS & set(wf.events()))
        if not pr_run and name != WARM:
            continue
        jobs, found = _reachable_jobs(wf)
        problems.extend(f"{name}: {problem}" for problem in found)
        for job_id, _job_wf, job in jobs:
            for step in job.steps():
                where = (name, job_id, step.label())
                uses = step.uses_name()
                text = "\n".join(step.lines)
                writes = False
                if uses == CACHE_COMBINED:
                    problems.append(f"{where}: actions/cache saves in its post step on every event")
                elif uses in EVENT_GATED_WRITERS:
                    writes = not _event_gated(step, EVENT_GATED_WRITERS[uses])
                elif uses in CONFIG_GATED_WRITERS:
                    set_inputs = sorted(set(CONFIG_GATED_WRITERS[uses][0]) & set(step.mapping("with")))
                    if set_inputs:
                        problems.append(f"{where}: {uses} sets {set_inputs}: name its gate")
                elif uses and uses not in NON_WRITER_ACTIONS:
                    problems.append(f"{where}: unclassified action {uses}")
                if not writes and CACHE_BACKEND_TEXT_RE.search(step.run()):
                    writes = True
                if writes and pr_run:
                    reached.append(where)
    return reached, problems


class PrRunCacheWriters9681(unittest.TestCase):
    """#9681 r1 (S1): no pull_request run writes a cache, except the named rows."""

    def test_every_pr_reachable_cache_writer_is_gated_or_named(self) -> None:
        reached, problems = _pr_cache_writers()
        self.assertEqual(problems, [])
        self.assertEqual(sorted(reached), sorted(PR_CACHE_WRITER_EXCEPTIONS))

    def test_local_actions_hold_no_cache_writer(self) -> None:
        for path in sorted(ACTIONS_LOCAL.rglob("action.y*ml")):
            with self.subTest(action=str(path.relative_to(REPO))):
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(re.search(r"^\s*(?:-\s+)?uses:", text, re.M))
                self.assertIsNone(CACHE_BACKEND_TEXT_RE.search(text))

    def test_writer_rules_table(self) -> None:
        def step(*lines: str) -> Step:
            return _parse_step([" " * STEP_INDENT + "- name: s", *(" " * KEY_INDENT + l for l in lines)])

        cases = [
            (step(f"uses: {RUST_CACHE}@{RUST_CACHE_SHA}", "with:", f"  save-if: {SAVE_IF_PUSH}"),
             "save-if", True),
            (step(f"uses: {RUST_CACHE}@{RUST_CACHE_SHA}"), "save-if", False),
            (step(f"uses: {RUST_CACHE}@{RUST_CACHE_SHA}", "with:", "  save-if: true"), "save-if", False),
            (step(f"if: {PUSH_GATE} && steps.r.outputs.cache-hit != 'true'"), "if", True),
            (step(f"if: {PUSH_GATE}"), "if", True),
            (step(f"if: {PUSH_GATE}x"), "if", False),
            (step("if: always()"), "if", False),
            (step(), "if", False),
            (step("with:", "  cache-to: type=gha,mode=max"), "cache-to", False),
            (step("with:", "  cache-from: type=gha"), "cache-to", True),
            (step("with:", "  cache-to: ${{ github.event_name == 'push' && 'type=gha' || '' }}"),
             "cache-to", True),
        ]
        for index, (candidate, how, expected) in enumerate(cases):
            with self.subTest(case=index):
                self.assertIs(_event_gated(candidate, how), expected)
        for text in ("SCCACHE_GHA_ENABLED=true sccache", "docker buildx build --cache-to type=gha",
                     "gh cache delete x", "curl $ACTIONS_CACHE_URL"):
            with self.subTest(text=text):
                self.assertIsNotNone(CACHE_BACKEND_TEXT_RE.search(text))
        self.assertIsNone(CACHE_BACKEND_TEXT_RE.search("cargo test --no-run; echo cache-hit"))


# --- #9681 r2 (D2 #9737): the key-env evaluator ----------------------------------------------------
#
# Rows: (raw env value, the leg's matrix entry, the value it takes, or None and the exact failure).
KEY_ENV_LITERAL = "line-tables-only"
KEY_ENV_MATRIX_FORM = "${{ matrix.cargo_debug || 'line-tables-only' }}"
KEY_ENV_EVAL_OK: tuple[tuple[str, str, dict[str, object], str], ...] = (
    ("literal", KEY_ENV_LITERAL, {}, KEY_ENV_LITERAL),
    ("literal-ignores-matrix", KEY_ENV_LITERAL, {"cargo_debug": "1"}, KEY_ENV_LITERAL),
    ("matrix-unset-takes-literal", KEY_ENV_MATRIX_FORM, {"leg": "ubuntu-latest,sqlite"},
     KEY_ENV_LITERAL),
    ("matrix-empty-takes-literal", KEY_ENV_MATRIX_FORM, {"cargo_debug": ""}, KEY_ENV_LITERAL),
    ("matrix-set-takes-matrix", KEY_ENV_MATRIX_FORM, {"cargo_debug": "1"}, "1"),
    ("tight-spacing", "${{matrix.cargo_debug||'full'}}", {}, "full"),
    ("empty-literal", "${{ matrix.x || '' }}", {}, ""),
)
KEY_ENV_EVAL_FAIL: tuple[tuple[str, str, dict[str, object], str], ...] = (
    ("other-context", "${{ env.X || 'a' }}", {},
     "K: unrecognised expression form in an env value: \"${{ env.X || 'a' }}\""),
    ("and-operator", "${{ matrix.a && 'b' }}", {},
     "K: unrecognised expression form in an env value: \"${{ matrix.a && 'b' }}\""),
    ("embedded", "pre-${{ matrix.a || 'b' }}", {},
     "K: unrecognised expression form in an env value: \"pre-${{ matrix.a || 'b' }}\""),
    ("bare-matrix", "${{ matrix.a }}", {},
     "K: unrecognised expression form in an env value: '${{ matrix.a }}'"),
    ("head-ref", "${{ github.head_ref }}", {},
     "K: unrecognised expression form in an env value: '${{ github.head_ref }}'"),
    ("two-defaults", "${{ matrix.a || matrix.b || 'c' }}", {},
     "K: unrecognised expression form in an env value: \"${{ matrix.a || matrix.b || 'c' }}\""),
    ("zero-is-ambiguous", KEY_ENV_MATRIX_FORM, {"cargo_debug": "0"},
     "K: matrix.cargo_debug = '0' is truthy when quoted and falsy when not, and this parser "
     "drops the quotes: \"${{ matrix.cargo_debug || 'line-tables-only' }}\""),
    ("boolean-is-ambiguous", KEY_ENV_MATRIX_FORM, {"cargo_debug": False},
     "K: matrix.cargo_debug = False is truthy when quoted and falsy when not, and this parser "
     "drops the quotes: \"${{ matrix.cargo_debug || 'line-tables-only' }}\""),
)


# --- #9681 r2 (D1 #9739): every hosted pull_request rust-cache site is paired or named ------------
#
# A site is one hosted leg of a job with a Swatinem/rust-cache step in a workflow a pull request
# can start. Each site is the PR job of a PAIRS row (a warm job writes its key) or a row of
# UNPAIRED_RUST_CACHE_SITES with the issue that owns its cold cost. A row that names no site is a
# failure, a site in neither is a failure, and so is one in both. A row that pins `commands` is
# also the spec of its future warm pair: its cold cargo commands (the ones rust-cache keeps) must
# be exactly the row's, so a new or changed command on that leg is a red until the row follows.


@dataclass(frozen=True)
class UnpairedSite:
    issues: tuple[int, ...]
    reason: str
    commands: tuple[str, ...] | None = None


# decision (b29, FIX-NOTICE-9681-r2): this table over a third warm pair for the android leg,
# because the leg is off the long pole. #9732 then paired it as LEG_PAIRS (a leg-level pair:
# the job's other leg, iOS, stays named here).
V12_COLD = ("vote V-12 accepted cost (#9681): no warm job, saves on push only; whether warm "
            "entries survive eviction is #9721")
V12_ISSUES = (9681, 9721)
UNPAIRED_RUST_CACHE_SITES: dict[tuple[str, str, str], UnpairedSite] = {
    ("ci.yml", "lint", ""): UnpairedSite(V12_ISSUES, V12_COLD),
    ("ci.yml", "postgres-feature", ""): UnpairedSite(V12_ISSUES, V12_COLD),
    ("ci.yml", "mobile-cross-compile", "target=aarch64-apple-ios"): UnpairedSite(V12_ISSUES, V12_COLD),
    ("ci.yml", "sal-feature", ""): UnpairedSite(V12_ISSUES, V12_COLD),
    ("ci.yml", "vectorlite-feature", ""): UnpairedSite(V12_ISSUES, V12_COLD),
    ("batman-mode-acceptance.yml", "rust-integration", ""): UnpairedSite(V12_ISSUES, V12_COLD),
    ("batman-mode-acceptance.yml", "bash-integration", ""): UnpairedSite(V12_ISSUES, V12_COLD),
    ("bench.yml", "bench", ""): UnpairedSite(V12_ISSUES, V12_COLD),
    ("mobile-runtime.yml", "ios-simulator", ""): UnpairedSite(V12_ISSUES, V12_COLD),
    ("mobile-runtime.yml", "android-emulator", ""): UnpairedSite(V12_ISSUES, V12_COLD),
    ("release-shape.yml", "release-shape", ""): UnpairedSite(V12_ISSUES, V12_COLD),
    ("token-budget.yml", "budget", ""): UnpairedSite(V12_ISSUES, V12_COLD),
}

RUNS_ON_MATRIX_RE = re.compile(
    r"^\$\{\{\s*(?:fromJSON\(\s*matrix\.([A-Za-z_][\w-]*)\s*\)|matrix\.([A-Za-z_][\w-]*))\s*\}\}$")
# #9821 (I5): the one flip condition `runs-on` may carry, written out by hand (the same text as
# LEG_SKIP in ci.yml); a changed or looser condition is an unrecognised runs-on form.
DRAFT_FLIP_CONDITION = (
    "github.event_name == 'pull_request' && github.event.pull_request.draft == true "
    "&& contains(matrix.runner, 'self-hosted') "
    "&& !contains(github.event.pull_request.labels.*.name, 'ci-fix')")
RUNS_ON_DRAFT_FLIP_RE = re.compile(
    r"""^\$\{\{\s*fromJSON\((.+) && '\["ubuntu-latest"\]' \|\| matrix\.(runner)\)\s*\}\}$""")
MATRIX_REF_RE = re.compile(r"\$\{\{\s*matrix\.([A-Za-z_][\w-]*)\s*\}\}")
SELF_HOSTED = "self-hosted"
SiteKey = tuple[str, str, str]


def _site_name(key: SiteKey) -> str:
    name, job_id, leg = key
    return f"{name}:{job_id}" + (f"[{leg}]" if leg else "")


def _runs_on(job: Job, leg: dict[str, object]) -> str:
    """The runner labels of one leg; a runs-on form other than a literal or a matrix read fails."""
    raw = job.scalar("runs-on")
    if not raw:
        raise AssertionError(f"{job.job_id}: runs-on is not a one-line scalar")
    if EXPRESSION_OPEN not in raw:
        return raw
    match = RUNS_ON_MATRIX_RE.match(raw.strip())
    is_flip = False
    if not match:
        # #9821 (I5): a draft PR flips a SELF-HOSTED leg to a hosted runner. The flip is
        # accepted only when its condition is exactly DRAFT_FLIP_CONDITION (which names
        # `contains(matrix.runner, 'self-hosted')`), so a hosted leg never changes; the leg's
        # own runner is the else branch.
        flip = RUNS_ON_DRAFT_FLIP_RE.match(raw.strip())
        if flip and flip.group(1) == DRAFT_FLIP_CONDITION:
            match = flip
            is_flip = True
    if not match:
        raise AssertionError(f"{job.job_id}: unrecognised runs-on form: {raw!r}")
    field_name = match.group(2) if is_flip else match.group(1) or match.group(2)
    if field_name not in leg:
        raise AssertionError(f"{job.job_id}: runs-on reads matrix.{field_name}, which leg "
                             f"{_leg_id(leg)!r} does not set")
    return str(leg[field_name])


def _maybe_reached(expr: str | None, leg: dict[str, object]) -> bool:
    """False only when the `if:` evaluator proves the condition false on a hosted PR leg."""
    if expr is None:
        return True
    try:
        return _eval_if(expr, leg)
    except AssertionError:
        return True


def _expand_matrix(command: str, leg: dict[str, object]) -> str:
    """Replace `${{ matrix.<name> }}` with a string value the leg sets; anything else stays."""
    def sub(match: re.Match[str]) -> str:
        value = leg.get(match.group(1))
        return value if isinstance(value, str) and value else match.group(0)
    return MATRIX_REF_RE.sub(sub, command)


def _hosted_pr_rust_cache_sites() -> tuple[dict[SiteKey, tuple[Workflow, Job, dict[str, object]]],
                                           list[str]]:
    """(every hosted PR-reachable rust-cache site, the problems) over every workflow file."""
    sites: dict[SiteKey, tuple[Workflow, Job, dict[str, object]]] = {}
    problems: list[str] = []
    for name in _all_workflow_names():
        wf = Workflow.load(name)
        if not PR_EVENTS & set(wf.events()):
            continue
        jobs, found = _reachable_jobs(wf)
        problems.extend(f"{name}: {problem}" for problem in found)
        for job_id, job_wf, job in jobs:
            caches = [s for s in job.steps() if s.uses_name() == RUST_CACHE]
            if not caches or not _maybe_reached(job.scalar("if"), {}):
                continue
            try:
                legs = _matrix_include(job) or [{}]
            except AssertionError as exc:
                problems.append(f"{name}: {exc}")
                continue
            for leg in legs:
                try:
                    runner = _runs_on(job, leg)
                except AssertionError as exc:
                    problems.append(f"{name}: {exc}")
                    continue
                if SELF_HOSTED in runner:
                    continue
                if any(_maybe_reached(s.keys.get("if"), leg) for s in caches):
                    _add_site(sites, problems, (name, job_id, _leg_id(leg)), (job_wf, job, leg))
    return sites, problems


def _add_site(sites: dict[SiteKey, tuple[Workflow, Job, dict[str, object]]],
              problems: list[str], key: SiteKey,
              value: tuple[Workflow, Job, dict[str, object]]) -> None:
    """Record one site; a second leg with the same key is a problem, never an overwrite (#9746)."""
    if key in sites:
        problems.append(f"two hosted legs of one job share the site key {_site_name(key)}: the "
                        f"second would overwrite the first; give them different first keys")
        return
    sites[key] = value


def _cold_commands(wf: Workflow, job: Job, leg: dict[str, object]) -> tuple[tuple[str, ...], list[str]]:
    """(the sorted cargo commands of one leg whose output rust-cache keeps, the problems)."""
    commands: set[str] = set()
    problems: list[str] = []
    for step in job.steps():
        found = _cargo_commands(step.run())
        if not found or not _maybe_reached(step.keys.get("if"), leg):
            continue
        env = {**wf.env(), **job.env(), **step.mapping("env")}
        for command in (_expand_matrix(_expand(c, env), leg) for c in found):
            sub = _subcommand(command)
            if sub in NON_PRODUCING_SUBCOMMANDS:
                continue
            if sub not in PRODUCING_SUBCOMMANDS:
                problems.append(f"{step.label()}: unclassified cargo subcommand: {command}")
            elif "$" in command:
                problems.append(f"{step.label()}: unnamed dynamic cargo command: {command}")
            else:
                commands.add(command)
    return tuple(sorted(commands)), problems


def _unpaired_site_problems(
        sites: frozenset[SiteKey], paired: frozenset[tuple[str, str]],
        table: dict[SiteKey, UnpairedSite],
        commands_of: Callable[[SiteKey], tuple[tuple[str, ...], list[str]]]) -> list[str]:
    """The fail-closed row rule of UNPAIRED_RUST_CACHE_SITES (pure: the caller supplies the sites)."""
    problems: list[str] = []
    for key in sorted(sites):
        in_pairs = key[:2] in paired
        in_table = key in table
        if in_pairs and in_table:
            problems.append(f"rust-cache site in both PAIRS and UNPAIRED_RUST_CACHE_SITES: "
                            f"{_site_name(key)}")
        elif not in_pairs and not in_table:
            problems.append(f"rust-cache site in neither PAIRS nor UNPAIRED_RUST_CACHE_SITES: "
                            f"{_site_name(key)}")
    for key in sorted(table):
        row = table[key]
        if key not in sites:
            problems.append(f"stale UNPAIRED_RUST_CACHE_SITES row (no hosted pull_request "
                            f"rust-cache site): {_site_name(key)}")
            continue
        if not row.issues or any(n <= 0 for n in row.issues):
            problems.append(f"UNPAIRED_RUST_CACHE_SITES row without an issue number: "
                            f"{_site_name(key)}")
        if row.commands is not None:
            actual, found = commands_of(key)
            problems.extend(f"{_site_name(key)}: {problem}" for problem in found)
            if actual != tuple(sorted(row.commands)):
                problems.append(
                    f"cold cargo commands of {_site_name(key)} differ from its row: only on the "
                    f"site {sorted(set(actual) - set(row.commands))}, only in the row "
                    f"{sorted(set(row.commands) - set(actual))}")
    site_jobs = {key[:2] for key in sites}
    for pair in sorted(paired - site_jobs):
        problems.append(f"PAIRS job with no hosted pull_request rust-cache site: "
                        f"{pair[0]}:{pair[1]}")
    return problems


class UnpairedRustCacheSites9681(unittest.TestCase):
    """#9681 r2: key env is evaluated per leg (D2 #9737); no rust-cache site is unaccounted (D1)."""

    def test_key_env_evaluator_table(self) -> None:
        for label, raw, leg, expected in KEY_ENV_EVAL_OK:
            with self.subTest(row=label):
                self.assertEqual(_effective_env_value("K", raw, leg), expected)
        for label, raw, leg, reason in KEY_ENV_EVAL_FAIL:
            with self.subTest(row=label):
                with self.assertRaises(AssertionError) as caught:
                    _effective_env_value("K", raw, leg)
                self.assertEqual(str(caught.exception), reason)

    def test_effective_key_env_keeps_key_prefixes_and_drops_empty(self) -> None:
        env = {"CARGO_X": KEY_ENV_MATRIX_FORM, "RUSTFLAGS": "${{ matrix.f || '' }}",
               "HOME_DIR": "${{ github.head_ref }}"}
        self.assertEqual(_effective_key_env(env, {"cargo_debug": "1"}), {"CARGO_X": "1"})
        with self.assertRaises(AssertionError) as caught:
            _effective_key_env({"CARGO_Y": "${{ secrets.X }}"}, {})
        self.assertEqual(str(caught.exception),
                         "CARGO_Y: unrecognised expression form in an env value: '${{ secrets.X }}'")

    def test_every_hosted_pr_rust_cache_site_is_paired_or_named(self) -> None:
        sites, problems = _hosted_pr_rust_cache_sites()
        self.assertEqual(problems, [])
        paired = frozenset((pr_name, pr_job) for pr_name, pr_job, _, _ in PAIRS)

        def commands_of(key: SiteKey) -> tuple[tuple[str, ...], list[str]]:
            wf, job, leg = sites[key]
            return _cold_commands(wf, job, leg)

        # #9732: a leg pair is a paired site of its own; the iOS leg of the same job stays named.
        self.assertEqual(sorted(set(LEG_PAIRS) - set(sites)), [], "LEG_PAIRS names no site")
        unpaired_candidates = frozenset(sites) - frozenset(LEG_PAIRS)
        self.assertEqual(_unpaired_site_problems(unpaired_candidates, paired,
                                                 UNPAIRED_RUST_CACHE_SITES, commands_of), [])

    def test_unpaired_row_rule_table(self) -> None:
        site_a, site_b, site_p = ("w.yml", "a", ""), ("w.yml", "b", "target=t"), ("w.yml", "p", "")
        paired = frozenset({("w.yml", "p")})
        cold = UnpairedSite((1,), "r")
        pinned = UnpairedSite((2,), "r", ("cargo build --release",))
        cmds: dict[SiteKey, tuple[tuple[str, ...], list[str]]] = {
            site_b: (("cargo build --release",), []),
        }

        def commands_of(key: SiteKey) -> tuple[tuple[str, ...], list[str]]:
            return cmds[key]

        cases: tuple[tuple[str, frozenset[SiteKey], dict[SiteKey, UnpairedSite], list[str]], ...] = (
            ("all-accounted", frozenset({site_a, site_b, site_p}),
             {site_a: cold, site_b: pinned}, []),
            ("site-in-neither", frozenset({site_a, site_p}), {},
             ["rust-cache site in neither PAIRS nor UNPAIRED_RUST_CACHE_SITES: w.yml:a"]),
            ("site-in-both", frozenset({site_p}), {site_p: cold},
             ["rust-cache site in both PAIRS and UNPAIRED_RUST_CACHE_SITES: w.yml:p"]),
            ("stale-row", frozenset({site_p}), {site_a: cold},
             ["stale UNPAIRED_RUST_CACHE_SITES row (no hosted pull_request rust-cache site): "
              "w.yml:a"]),
            ("row-without-issue", frozenset({site_a, site_p}), {site_a: UnpairedSite((), "r")},
             ["UNPAIRED_RUST_CACHE_SITES row without an issue number: w.yml:a"]),
            ("row-with-zero-issue", frozenset({site_a, site_p}), {site_a: UnpairedSite((0,), "r")},
             ["UNPAIRED_RUST_CACHE_SITES row without an issue number: w.yml:a"]),
            ("paired-job-without-site", frozenset({site_a}), {site_a: cold},
             ["PAIRS job with no hosted pull_request rust-cache site: w.yml:p"]),
        )
        for label, sites, table, expected in cases:
            with self.subTest(row=label):
                self.assertEqual(_unpaired_site_problems(sites, paired, table, commands_of),
                                 expected)
        for label, actual in (("command-added", ("cargo build --release", "cargo install x")),
                              ("command-changed", ("cargo build --release --features sal",))):
            with self.subTest(row=label):
                cmds[site_b] = (actual, [])
                only_site = sorted(set(actual) - {"cargo build --release"})
                only_row = sorted({"cargo build --release"} - set(actual))
                self.assertEqual(
                    _unpaired_site_problems(frozenset({site_b, site_p}), paired,
                                            {site_b: pinned}, commands_of),
                    [f"cold cargo commands of w.yml:b[target=t] differ from its row: only on the "
                     f"site {only_site}, only in the row {only_row}"])
        cmds[site_b] = ((), ["s: unnamed dynamic cargo command: cargo build $X"])
        self.assertEqual(
            _unpaired_site_problems(frozenset({site_b, site_p}), paired, {site_b: pinned},
                                    commands_of),
            ["w.yml:b[target=t]: s: unnamed dynamic cargo command: cargo build $X",
             "cold cargo commands of w.yml:b[target=t] differ from its row: only on the site [], "
             "only in the row ['cargo build --release']"])

    def test_runs_on_reader_table_and_fail_closed(self) -> None:
        def job(runs_on: str) -> Job:
            return Job("j", [f"    runs-on: {runs_on}"])

        leg = {"os": "ubuntu-latest", "runner": '["self-hosted","linux-fed"]'}
        flip_text = "${{ fromJSON(%s && '[\"ubuntu-latest\"]' || matrix.runner) }}"
        draft_flip_form = flip_text % DRAFT_FLIP_CONDITION
        cases = {
            "ubuntu-latest": "ubuntu-latest",
            "[self-hosted, linux-fed]": "[self-hosted, linux-fed]",
            "${{ matrix.os }}": "ubuntu-latest",
            "${{ fromJSON(matrix.runner) }}": '["self-hosted","linux-fed"]',
            draft_flip_form: '["self-hosted","linux-fed"]',
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(_runs_on(job(raw), leg), expected)
        failures = {
            "${{ inputs.runner }}": "j: unrecognised runs-on form: '${{ inputs.runner }}'",
            "${{ matrix.missing }}": "j: runs-on reads matrix.missing, which leg "
                                     "'os=ubuntu-latest' does not set",
        }
        # A flip whose condition is not exactly the pinned one is refused: a dropped
        # self-hosted test, a dropped ci-fix exemption, an `||` tail, or a changed event.
        for changed in (
            DRAFT_FLIP_CONDITION.replace(" && contains(matrix.runner, 'self-hosted')", ""),
            DRAFT_FLIP_CONDITION.replace(
                " && !contains(github.event.pull_request.labels.*.name, 'ci-fix')", ""),
            DRAFT_FLIP_CONDITION + " || true",
            DRAFT_FLIP_CONDITION.replace("'pull_request'", "'push'"),
            "contains(matrix.runner, 'self-hosted')",
        ):
            failures[flip_text % changed] = (
                "j: unrecognised runs-on form: " + repr(flip_text % changed))
        for raw, reason in failures.items():
            with self.subTest(raw=raw), self.assertRaises(AssertionError) as caught:
                _runs_on(job(raw), leg)
            self.assertEqual(str(caught.exception), reason)

    def test_readers_are_linear_on_large_values(self) -> None:
        """A 200K-character env value or runs-on is read in well under a second, failing closed."""
        size = 200_000
        cases = (
            ("${{ matrix.a || '" + "x" * size + "' }}", {}, "x" * size),
            ("${{ matrix.a " + " " * size + "|| 'b' }}", {}, "b"),
        )
        for raw, leg, expected in cases:
            started = time.monotonic()
            self.assertEqual(_effective_env_value("K", raw, leg), expected)
            self.assertLess(time.monotonic() - started, 1.0)
        for raw in ("${{ matrix.a || '" + "x" * size, "${{ " + " " * size + "matrix.a |",
                    "${{ matrix.a || '" + "'" * size + " }}"):
            started = time.monotonic()
            with self.assertRaises(AssertionError) as caught:
                _effective_env_value("K", raw, {})
            self.assertLess(time.monotonic() - started, 1.0)
            self.assertTrue(str(caught.exception).startswith(
                "K: unrecognised expression form in an env value: "))
        started = time.monotonic()
        with self.assertRaises(AssertionError) as caught:
            _runs_on(Job("j", ["    runs-on: ${{ fromJSON(matrix." + "a" * size + " }}"]), {})
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertTrue(str(caught.exception).startswith("j: unrecognised runs-on form: "))

    def test_hosted_legs_read_runs_on_and_fail_closed(self) -> None:
        """Sibling (#9681 r2): the PAIRS leg filter reads `runs-on`, not one matrix field's text."""
        def job(runs_on: str, *legs: str) -> Job:
            lines = [f"    runs-on: {runs_on}"]
            if legs:  # an `include:` with no entries is a refused form (#9745 r1), so no strategy
                lines += ["    strategy:", "      matrix:", "        include:"]
                lines += [f"          - {leg}" for leg in legs]
            return Job("j", lines)

        by_os = job("${{ matrix.os }}", "os: ubuntu-latest", "os: '[self-hosted, linux-fed]'")
        self.assertEqual(_hosted_legs(by_os), [{"os": "ubuntu-latest"}])
        self.assertEqual(_hosted_legs(job("[self-hosted, linux-fed]")), [])
        self.assertEqual(_hosted_legs(job("ubuntu-latest")), [{}])
        with self.assertRaises(AssertionError) as caught:
            _hosted_legs(job("${{ inputs.runner }}", "runner: ubuntu-latest"))
        self.assertEqual(str(caught.exception),
                         "j: unrecognised runs-on form: '${{ inputs.runner }}'")


# --- #9681 r3 (#9745, #9746, #9747) ----------------------------------------------------------------
# Hand-written expected columns. Each unquoted spelling the YAML 1.2 core schema types as
# something other than a string, with the form the refusal names.
UNQUOTED_TYPED_FORMS: tuple[tuple[str, str], ...] = (
    ("null", "null"), ("Null", "null"), ("NULL", "null"), ("~", "null"),
    ("true", "boolean"), ("True", "boolean"), ("TRUE", "boolean"),
    ("false", "boolean"), ("False", "boolean"), ("FALSE", "boolean"),
    ("0x0", "integer"), ("0x1F", "integer"), ("0o7", "integer"), ("+1", "integer"),
    ("01", "integer"), ("00", "integer"), ("-01", "integer"),
    ("1.0", "float"), ("0.0e0", "float"), ("1e3", "float"), (".5", "float"), ("5.", "float"),
    ("-0.0", "float"), (".nan", "float"), (".NaN", "float"), (".NAN", "float"),
    (".inf", "float"), ("-.inf", "float"), ("+.INF", "float"),
)
# Unquoted text and canonical non-zero integers render as themselves: taken as written.
UNQUOTED_TEXT_ROWS: tuple[str, ...] = ("1", "-5", "12", "debug", "line-tables-only", "1x", "0b1",
                                       "nulls", "1_000", "0x", ".", "e3")
# Quoted spellings are strings whatever they spell: taken as written.
QUOTED_TEXT_ROWS: tuple[str, ...] = ("null", "~", "0", "0.0", "False", "0x0", "1.0", ".nan", "true")
UNQUOTED_FORM_MESSAGE = ("K: matrix.cargo_debug = {value!r} is an unquoted YAML {form}, which the "
                         "runner reads as a typed value, not as this text: "
                         "\"${{{{ matrix.cargo_debug || 'line-tables-only' }}}}\"")

STUB_SHA = "0" * 40
STUB_CACHE_STEP = (f"      - name: Cache\n        uses: {RUST_CACHE}@{STUB_SHA}\n"
                   "        with:\n          save-if: ${{ github.event_name == 'push' }}\n")


def _stub_workflow(event: str, jobs: str) -> str:
    return f"name: stub\non:\n  {event}:\njobs:\n{jobs}"


def _stub_job(job_id: str, matrix: str = "", steps: str = STUB_CACHE_STEP) -> str:
    return f"  {job_id}:\n    runs-on: ubuntu-latest\n{matrix}    steps:\n{steps}"


def _stub_matrix(*legs: str) -> str:
    body = "".join(f"          - {leg}\n" for leg in legs)
    return f"    strategy:\n      matrix:\n        include:\n{body}"


def _with_stub_workflows(texts: dict[str, str]):
    """Patch the workflow tree seen by the enumerators to in-memory text (no file is written)."""
    from unittest import mock
    module = sys.modules[__name__]

    def load(name: str) -> Workflow:
        return Workflow(name, texts[name].splitlines())

    stack = mock.patch.object(module, "_all_workflow_names", lambda: sorted(texts))
    load_patch = mock.patch.object(Workflow, "load", staticmethod(load))
    return stack, load_patch


class ReachableWorkflowSites9681R3(unittest.TestCase):
    """#9681 r3: the key-env evaluator reads typed YAML (#9745); the site enumerator names every
    leg (#9746) and follows job-level `uses:` (#9747)."""

    def _sites(self, texts: dict[str, str]):
        names_patch, load_patch = _with_stub_workflows(texts)
        with names_patch, load_patch:
            return _hosted_pr_rust_cache_sites()

    def _writers(self, texts: dict[str, str]):
        names_patch, load_patch = _with_stub_workflows(texts)
        with names_patch, load_patch:
            return _pr_cache_writers()

    def test_unquoted_typed_matrix_values_are_refused_naming_the_form(self) -> None:
        for value, form in UNQUOTED_TYPED_FORMS:
            with self.subTest(value=value):
                with self.assertRaises(AssertionError) as caught:
                    _effective_env_value("K", KEY_ENV_MATRIX_FORM, {"cargo_debug": value})
                self.assertEqual(str(caught.exception),
                                 UNQUOTED_FORM_MESSAGE.format(value=value, form=form))

    def test_unquoted_text_and_quoted_values_are_taken_as_written(self) -> None:
        for value in UNQUOTED_TEXT_ROWS:
            with self.subTest(value=value, quoted=False):
                self.assertEqual(
                    _effective_env_value("K", KEY_ENV_MATRIX_FORM, {"cargo_debug": value}), value)
        for value in QUOTED_TEXT_ROWS:
            for quote in ("'", '"'):
                with self.subTest(value=value, quote=quote):
                    job = Job("j", ["    runs-on: x", "    strategy:", "      matrix:",
                                    "        include:",
                                    f"          - cargo_debug: {quote}{value}{quote}"])
                    (leg,) = _matrix_include(job)
                    self.assertEqual(_effective_env_value("K", KEY_ENV_MATRIX_FORM, leg), value)

    def test_unquoted_matrix_spelling_is_refused_end_to_end(self) -> None:
        for value, form in (("null", "null"), ("0x0", "integer"), ("1.0", "float")):
            with self.subTest(value=value):
                job = Job("j", ["    runs-on: x", "    strategy:", "      matrix:",
                                "        include:", f"          - cargo_debug: {value}"])
                (leg,) = _matrix_include(job)
                with self.assertRaises(AssertionError) as caught:
                    _effective_env_value("K", KEY_ENV_MATRIX_FORM, leg)
                self.assertEqual(str(caught.exception),
                                 UNQUOTED_FORM_MESSAGE.format(value=value, form=form))

    def test_two_hosted_legs_with_one_first_key_are_a_problem(self) -> None:
        legs = _stub_matrix("target: t", "target: t\n            os: other")
        sites, problems = self._sites({"w.yml": _stub_workflow(
            "pull_request", _stub_job("m", legs))})
        self.assertEqual(sorted(sites), [("w.yml", "m", "target=t")])
        self.assertEqual(problems, ["two hosted legs of one job share the site key "
                                    "w.yml:m[target=t]: the second would overwrite the first; "
                                    "give them different first keys"])
        legs = _stub_matrix("target: t", "target: u")
        sites, problems = self._sites({"w.yml": _stub_workflow(
            "pull_request", _stub_job("m", legs))})
        self.assertEqual((sorted(sites), problems),
                         ([("w.yml", "m", "target=t"), ("w.yml", "m", "target=u")], []))

    def test_called_workflow_jobs_are_sites_of_the_caller(self) -> None:
        call = "  call:\n    uses: ./.github/workflows/called.yml\n"
        texts = {"caller.yml": _stub_workflow("pull_request", call),
                 "called.yml": _stub_workflow("workflow_call", _stub_job("inner"))}
        sites, problems = self._sites(texts)
        self.assertEqual((sorted(sites), problems), ([("caller.yml", "call/inner", "")], []))
        # the same workflow behind a push-only caller is not reached by a pull request
        texts["caller.yml"] = _stub_workflow("push", call)
        self.assertEqual(self._sites(texts), ({}, []))
        # two levels
        texts = {"a.yml": _stub_workflow("pull_request", "  x:\n    uses: ./.github/workflows/b.yml\n"),
                 "b.yml": _stub_workflow("workflow_call", "  y:\n    uses: ./.github/workflows/c.yml\n"),
                 "c.yml": _stub_workflow("workflow_call", _stub_job("z"))}
        sites, problems = self._sites(texts)
        self.assertEqual((sorted(sites), problems), ([("a.yml", "x/y/z", "")], []))

    def test_unreadable_reusable_workflow_calls_fail_closed(self) -> None:
        forms = {
            "remote": ("owner/repo/.github/workflows/r.yml@v1",
                       "job-level uses of a reusable workflow that is not a local "
                       "./.github/workflows/<name>.yml: 'owner/repo/.github/workflows/r.yml@v1'"),
            "local-with-ref": ("./.github/workflows/called.yml@main",
                               "job-level uses of a reusable workflow that is not a local "
                               "./.github/workflows/<name>.yml: './.github/workflows/called.yml@main'"),
            "outside-tree": ("./other/called.yml",
                             "job-level uses of a reusable workflow that is not a local "
                             "./.github/workflows/<name>.yml: './other/called.yml'"),
            "subdirectory": ("./.github/workflows/sub/called.yml",
                             "job-level uses of a reusable workflow that is not a local "
                             "./.github/workflows/<name>.yml: './.github/workflows/sub/called.yml'"),
            "missing": ("./.github/workflows/nothere.yml",
                        "reusable workflow './.github/workflows/nothere.yml' is not a file"),
        }
        for label, (uses, reason) in forms.items():
            with self.subTest(form=label):
                texts = {"caller.yml": _stub_workflow("pull_request", f"  call:\n    uses: {uses}\n"),
                         "called.yml": _stub_workflow("workflow_call", _stub_job("inner"))}
                for fn in (self._sites, self._writers):
                    result = fn(texts)
                    self.assertEqual(result[1], [f"caller.yml: call: {reason}"])
        cycle = {"a.yml": _stub_workflow("pull_request", "  x:\n    uses: ./.github/workflows/b.yml\n"),
                 "b.yml": _stub_workflow("workflow_call", "  y:\n    uses: ./.github/workflows/b.yml\n")}
        self.assertEqual(self._sites(cycle)[1], [
            "a.yml: x/y: reusable workflow call cycle: './.github/workflows/b.yml'"])
        self.assertEqual(self._writers(cycle)[1], [
            "a.yml: x/y: reusable workflow call cycle: './.github/workflows/b.yml'"])

    def _chain(self, last: int) -> dict[str, str]:
        """w0 (a pull_request workflow) calls w1 ... calls w<last>, which holds the job `leaf`."""
        names = [f"w{n}.yml" for n in range(last + 1)]
        texts = {name: _stub_workflow(
            "pull_request" if n == 0 else "workflow_call",
            f"  c:\n    uses: ./.github/workflows/{names[n + 1]}\n")
            for n, name in enumerate(names[:-1])}
        texts[names[-1]] = _stub_workflow("workflow_call", _stub_job("leaf"))
        return texts

    def test_call_chain_one_deeper_than_the_limit_is_refused_as_too_deep(self) -> None:
        # w0 .. w9: the call of w9 comes from w8, whose trail already holds eight workflows.
        sites, problems = self._sites(self._chain(9))
        self.assertEqual(sites, {})
        self.assertEqual(problems, [
            "w0.yml: c/c/c/c/c/c/c/c/c: reusable workflow call chain deeper than 8: "
            "'./.github/workflows/w9.yml'"])
        self.assertEqual(self._writers(self._chain(9))[1], problems)

    def test_call_chain_at_the_limit_is_followed(self) -> None:
        # w0 .. w8: eight calls, the last job is `leaf`.
        sites, problems = self._sites(self._chain(8))
        self.assertEqual((sorted(sites), problems), ([("w0.yml", "c/c/c/c/c/c/c/c/leaf", "")], []))
        sites, problems = self._sites(self._chain(7))
        self.assertEqual((sorted(sites), problems), ([("w0.yml", "c/c/c/c/c/c/c/leaf", "")], []))

    def test_call_chain_messages_name_which_limit_fired(self) -> None:
        cycle = {"a.yml": _stub_workflow("pull_request", "  x:\n    uses: ./.github/workflows/b.yml\n"),
                 "b.yml": _stub_workflow("workflow_call", "  y:\n    uses: ./.github/workflows/a.yml\n")}
        self.assertEqual(self._sites(cycle)[1], [
            "a.yml: x/y: reusable workflow call cycle: './.github/workflows/a.yml'"])
        self.assertNotIn("deeper", self._sites(cycle)[1][0])
        self.assertNotIn("cycle", self._sites(self._chain(9))[1][0])

    def test_cache_writer_in_a_called_workflow_is_reached(self) -> None:
        writer = ("      - name: Docker layers\n        uses: actions/cache@" + STUB_SHA + "\n")
        call = "  call:\n    uses: ./.github/workflows/called.yml\n"
        texts = {"caller.yml": _stub_workflow("pull_request", call),
                 "called.yml": _stub_workflow("workflow_call", _stub_job("inner", steps=writer))}
        reached, problems = self._writers(texts)
        self.assertEqual(problems, ["('caller.yml', 'call/inner', 'Docker layers'): actions/cache "
                                    "saves in its post step on every event"])
        texts["caller.yml"] = _stub_workflow("push", call)
        self.assertEqual(self._writers(texts), ([], []))


# --- #9745 r1 (L3): the three save-scope checks read the jobs a PR run reaches ------------------
FOREIGN_SHA = "1" * 40
CALLER_CALLS_INNER = "  call:\n    uses: ./.github/workflows/inner.yml\n"
FOREIGN_RUST_CACHE_STEP = (
    f"      - name: Cache\n        uses: {RUST_CACHE}@{FOREIGN_SHA}\n        with:\n"
    "          save-if: ${{ github.event_name == 'push' }}\n          cache-on-failure: true\n")
UNGATED_CACHE_STEPS = (
    f"      - name: Docker layers\n        uses: actions/cache@{STUB_SHA}\n"
    f"      - name: Save it\n        uses: actions/cache/save@{STUB_SHA}\n        if: always()\n")
REMOTE_CALL = "owner/repo/.github/workflows/r.yml@v1"
REMOTE_CALL_PROBLEM = ("caller.yml: call: job-level uses of a reusable workflow that is not a "
                       "local ./.github/workflows/<name>.yml: 'owner/repo/.github/workflows/r.yml@v1'")


def _caller_and_inner(steps: str, event: str = "pull_request", call: str = CALLER_CALLS_INNER
                      ) -> dict[str, str]:
    return {"caller.yml": _stub_workflow(event, call),
            "inner.yml": _stub_workflow("workflow_call", _stub_job("inner", steps=steps))}


def _under_stubs(texts: dict[str, str], fn: Callable, *args):
    names_patch, load_patch = _with_stub_workflows(texts)
    with names_patch, load_patch:
        return fn(*args)


class CalledWorkflowSaveScope9745R1(unittest.TestCase):
    """#9745 r1 L3: the hand-table, pin and no-PR-cache checks follow a job-level `uses:` like the
    site enumerator does (a foreign sha and cache-on-failure inside a called workflow are found)."""

    def test_site_count_follows_a_called_workflow(self) -> None:
        texts = _caller_and_inner(FOREIGN_RUST_CACHE_STEP)
        self.assertEqual(_under_stubs(texts, _rust_cache_site_counts),
                         ({"caller.yml": {"call/inner": 1}}, []))

    def test_pin_and_on_failure_checks_follow_a_called_workflow(self) -> None:
        texts = _caller_and_inner(FOREIGN_RUST_CACHE_STEP)
        self.assertEqual(_under_stubs(texts, _rust_cache_step_failures, ["caller.yml"]), [
            f"caller.yml:call/inner: rust-cache sha {FOREIGN_SHA!r} is not the pinned "
            f"{RUST_CACHE_SHA}",
            "caller.yml:call/inner: cache-on-failure is set"])

    def test_pr_cache_action_check_follows_a_called_workflow(self) -> None:
        texts = _caller_and_inner(UNGATED_CACHE_STEPS)
        self.assertEqual(_under_stubs(texts, _pr_cache_action_failures), [
            "caller.yml:call/inner: Docker layers: actions/cache saves in its post step on every "
            "event",
            "caller.yml:call/inner: Save it: cache save is not gated on a push: 'always()'"])
        texts = _caller_and_inner(UNGATED_CACHE_STEPS, event="push")
        self.assertEqual(_under_stubs(texts, _pr_cache_action_failures), [])

    def test_an_unreadable_call_is_reported_by_each_check(self) -> None:
        texts = _caller_and_inner(
            FOREIGN_RUST_CACHE_STEP, call=f"  call:\n    uses: {REMOTE_CALL}\n")
        self.assertEqual(_under_stubs(texts, _rust_cache_site_counts), ({}, [REMOTE_CALL_PROBLEM]))
        self.assertEqual(_under_stubs(texts, _rust_cache_step_failures, ["caller.yml"]),
                         [REMOTE_CALL_PROBLEM])
        self.assertEqual(_under_stubs(texts, _pr_cache_action_failures), [REMOTE_CALL_PROBLEM])

    def test_shared_key_owners_follow_a_called_workflow(self) -> None:
        steps = (f"      - name: Cache\n        uses: {RUST_CACHE}@{STUB_SHA}\n        with:\n"
                 "          shared-key: k\n")
        texts = _caller_and_inner(steps)
        self.assertEqual(_under_stubs(texts, _shared_key_owners, ["caller.yml"]),
                         {"k": ["caller.yml:call/inner"]})

    def test_shared_key_owners_refuse_an_unreadable_call(self) -> None:
        texts = _caller_and_inner(
            FOREIGN_RUST_CACHE_STEP, call=f"  call:\n    uses: {REMOTE_CALL}\n")
        with self.assertRaises(AssertionError) as caught:
            _under_stubs(texts, _shared_key_owners, ["caller.yml"])
        self.assertEqual(str(caught.exception), REMOTE_CALL_PROBLEM)


class StrategyStructureRefusals9745R1(unittest.TestCase):
    """#9745 r1: strategy, matrix and include structure forms the first hand-mutant run found
    unpinned (each case is red on a mutant that drops its branch)."""

    @staticmethod
    def _strategy_job(*lines: str) -> Job:
        return Job("j", ["    runs-on: x", "    strategy:", *lines])

    def test_structure_refusals(self) -> None:
        include = ["        include:", "          - target: t"]
        cases = (
            (["      fail-fast: false", "        extra: 1", "      matrix:", *include],
             "j: strategy.fail-fast", R_NESTED, "extra: 1"),
            (["      matrix:", *include, "      matrix:", *include],
             "j: strategy", R_DUPLICATE, "matrix:"),
            (["      matrix:", *include, "        include:", "          - target: u"],
             "j: strategy.matrix", R_DUPLICATE, "include:"),
            (["        fail-fast: false", "      matrix:", *include],
             "j: strategy", R_INDENT, "matrix:"),
            (["      matrix:", "        include:", "          target: t"],
             "j: strategy.matrix.include", R_INCLUDE_BLOCK, "target: t"),
            (["      matrix:", "        include:", "          -x: 1"],
             "j: strategy.matrix.include[0]", R_LINE, "-x: 1"),
            (["      matrix:", *include, "          cargo_debug: 1"],
             "j: strategy.matrix.include[0]", R_INDENT, "cargo_debug: 1"),
        )
        for lines, where, reason, text in cases:
            with self.subTest(reason=reason, text=text):
                with self.assertRaises(UnreadForm) as caught:
                    _matrix_include(self._strategy_job(*lines))
                self.assertEqual(str(caught.exception), _unread(where, reason, text))

    def test_a_strategy_without_a_matrix_has_no_legs(self) -> None:
        self.assertEqual(_matrix_include(self._strategy_job("      fail-fast: false")), [])
        self.assertEqual(_matrix_include(Job("j", ["    runs-on: x"])), [])


class AddSiteFirstWins9746R1(unittest.TestCase):
    """#9745 r1 (surviving mutant M3): the first leg of a key stays recorded; the second is a
    problem. Sentinel values make a dropped early `return` (second overwrites first) visible."""

    def test_a_second_leg_with_the_same_key_never_replaces_the_first(self) -> None:
        sites: dict = {}
        problems: list[str] = []
        key = ("w.yml", "m", "target=t")
        first, second, third = ("wf-1", "job-1", {"n": 1}), ("wf-2", "job-2", {"n": 2}), \
            ("wf-3", "job-3", {"n": 3})
        _add_site(sites, problems, key, first)
        self.assertEqual((sites, problems), ({key: first}, []))
        _add_site(sites, problems, key, second)
        self.assertIs(sites[key], first)
        self.assertEqual(problems, ["two hosted legs of one job share the site key "
                                    "w.yml:m[target=t]: the second would overwrite the first; "
                                    "give them different first keys"])
        other = ("w.yml", "m", "target=u")
        _add_site(sites, problems, other, third)
        self.assertEqual((sites, len(problems)), ({key: first, other: third}, 1))


# --- #9745 r1 (L2): one closed-list decoder; an unread form is refused by name ------------------
EXPRESSION_DEFAULT = "line-tables-only"
LEG_HEAD = ["    runs-on: x", "    strategy:", "      matrix:", "        include:"]
LEG_WHERE = "j: strategy.matrix.include[0].cargo_debug"
TRUTHY_ZERO_MESSAGE = ("K: matrix.cargo_debug = '0' is truthy when quoted and falsy when not, and "
                       "this parser drops the quotes: " + repr(KEY_ENV_MATRIX_FORM))
# Reason strings, written out here (the code under test must produce exactly these).
R_FLOW_MAPPING, R_FLOW_SEQUENCE = "flow mapping", "flow sequence"
R_BLOCK_SCALAR, R_ALIAS, R_ANCHOR, R_TAG = "block scalar", "alias", "anchor", "tag"
R_EXPRESSION = "expression"
R_AFTER_QUOTE = "text after the closing quote"
R_UNTERMINATED = "unterminated quote"
R_ESCAPE = "escape in a double-quoted scalar"
R_COLON = "colon in a plain scalar"
R_RESERVED = "reserved indicator"
R_FLOW_INDICATOR = "flow indicator at the start of a plain scalar"
R_BLOCK_INDICATOR = "block collection indicator"
R_CONTROL = "control character"
R_NESTED = "nested or continued value"
R_INDENT = "mis-indented line"
R_DUPLICATE = "duplicate key"
R_LINE = "line that is not key: value with a plain identifier key"
R_BARE_DASH = "list entry that does not start with a key on the dash line"
R_AXIS = "matrix axis"
R_STRATEGY_BLOCK = "strategy is not a block mapping"
R_STRATEGY_KEY = "strategy key other than fail-fast, max-parallel and matrix"
R_MATRIX_BLOCK = "matrix is not a block mapping"
R_INCLUDE_BLOCK = "include is not a block list"


def _unread(where: str, reason: str, text: str) -> str:
    return f"{where}: unread YAML form, {reason}: {text!r}"


def _leg_job(*lines: str) -> Job:
    return Job("j", [*LEG_HEAD, *lines])


def _leg_outcome(written: str, after_colon: str = " ") -> tuple[str, object]:
    """What the leg `cargo_debug:<after_colon><written>` gives the key env: ("value", text) or
    ("refused", the refusal text)."""
    job = _leg_job("          - target: t", f"            cargo_debug:{after_colon}{written}")
    try:
        (leg,) = _matrix_include(job)
        return "value", _effective_env_value("K", KEY_ENV_MATRIX_FORM, leg)
    except AssertionError as exc:
        return "refused", str(exc)


# (body, quoting, written, expected). expected is ("value", text), ("unread", reason) or
# ("refused", the exact message). The comment and whitespace variants are generated below.
CORPUS_ROWS: tuple[tuple[str, str, str, tuple[str, str]], ...] = (
    ("abc", "none", "abc", ("value", "abc")),
    ("abc", "single", "'abc'", ("value", "abc")),
    ("abc", "double", '"abc"', ("value", "abc")),
    ("it's", "none", "it's", ("value", "it's")),
    ("it's", "single", "'it''s'", ("value", "it's")),
    ("it's", "double", '"it\'s"', ("value", "it's")),
    ("12", "none", "12", ("value", "12")),
    ("12", "single", "'12'", ("value", "12")),
    ("12", "double", '"12"', ("value", "12")),
    ("zero", "none", "0", ("refused", TRUTHY_ZERO_MESSAGE)),
    ("zero", "single", "'0'", ("value", "0")),
    ("zero", "double", '"0"', ("value", "0")),
    ("empty", "none", "", ("value", EXPRESSION_DEFAULT)),
    ("empty", "single", "''", ("value", EXPRESSION_DEFAULT)),
    ("empty", "double", '""', ("value", EXPRESSION_DEFAULT)),
    ("hash", "none", "a#b", ("value", "a#b")),
    ("hash", "single", "'a #b'", ("value", "a #b")),
    ("hash", "double", '"a #b"', ("value", "a #b")),
    ("json", "single", """'["ubuntu-latest"]'""", ("value", '["ubuntu-latest"]')),
    ("comma", "none", "ubuntu-latest,sqlite", ("value", "ubuntu-latest,sqlite")),
)
AFTER_COLON_VARIANTS = (" ", "   ")
TAIL_VARIANTS = ("", "  ")
COMMENT_VARIANTS = ("", " # c", "   # it's a 'comment' \"here\"")
# (written, reason): every form the evaluator cannot read as one string is refused by name.
REFUSED_FORMS: tuple[tuple[str, str], ...] = (
    ("{a: 1}", R_FLOW_MAPPING), ("{}", R_FLOW_MAPPING),
    ("[0]", R_FLOW_SEQUENCE), ("[0, 1]", R_FLOW_SEQUENCE), ("[]", R_FLOW_SEQUENCE),
    (">-", R_BLOCK_SCALAR), ("|", R_BLOCK_SCALAR), (">", R_BLOCK_SCALAR), ("|+", R_BLOCK_SCALAR),
    ("*d", R_ALIAS), ("&d 0", R_ANCHOR), ("!!str 0", R_TAG), ("!x 0", R_TAG),
    ("${{ inputs.d }}", R_EXPRESSION), ("'${{ inputs.d }}'", R_EXPRESSION),
    ('"${{ inputs.d }}"', R_EXPRESSION), ("pre-${{ inputs.d }}", R_EXPRESSION),
    ("'0'#c", R_AFTER_QUOTE), ("'a' b", R_AFTER_QUOTE), ('"a"b', R_AFTER_QUOTE),
    ("'a", R_UNTERMINATED), ('"a', R_UNTERMINATED), ("'a''", R_UNTERMINATED),
    ('"a\\n"', R_ESCAPE), ('"a\\"b"', R_ESCAPE),
    ("a: b", R_COLON),
    ("@x", R_RESERVED), ("`x", R_RESERVED), ("%x", R_RESERVED),
    (",x", R_FLOW_INDICATOR), ("]x", R_FLOW_INDICATOR), ("}x", R_FLOW_INDICATOR),
    ("- x", R_BLOCK_INDICATOR), ("-", R_BLOCK_INDICATOR), ("? x", R_BLOCK_INDICATOR),
    ("a\x01b", R_CONTROL),
)


class UnreadFormRefusals9745R1(unittest.TestCase):
    """#9745 r1 L2: a matrix leg value, an env value or a key part is evaluated to the exact string
    the runner uses, or refused naming the unread form. No default and no raw text is returned for
    a form the reader does not model."""

    def test_generated_corpus_evaluates_exactly(self) -> None:
        count = 0
        for body, quoting, written, expected in CORPUS_ROWS:
            for after in AFTER_COLON_VARIANTS:
                for tail in TAIL_VARIANTS:
                    for comment in COMMENT_VARIANTS:
                        text = written + tail + comment
                        with self.subTest(body=body, quoting=quoting, after=after, tail=tail,
                                          comment=comment):
                            count += 1
                            kind, want = expected
                            if kind == "value":
                                self.assertEqual(_leg_outcome(text, after), ("value", want))
                            elif kind == "unread":
                                self.assertEqual(_leg_outcome(text, after), (
                                    "refused", _unread(LEG_WHERE, want, text.strip())))
                            else:
                                self.assertEqual(_leg_outcome(text, after), ("refused", want))
        self.assertEqual(count, len(CORPUS_ROWS) * len(AFTER_COLON_VARIANTS)
                         * len(TAIL_VARIANTS) * len(COMMENT_VARIANTS))

    def test_unreadable_leg_forms_are_refused_by_name(self) -> None:
        for written, reason in REFUSED_FORMS:
            for after in AFTER_COLON_VARIANTS:
                with self.subTest(written=written, after=after):
                    self.assertEqual(_leg_outcome(written, after), (
                        "refused", _unread(LEG_WHERE, reason, written.strip())))

    def test_the_comment_does_not_hide_an_unread_form(self) -> None:
        for written, reason in (("*d", R_ALIAS), ("[0]", R_FLOW_SEQUENCE), ("!!str 0", R_TAG)):
            with self.subTest(written=written):
                text = f"{written} # c"
                self.assertEqual(_leg_outcome(text), (
                    "refused", _unread(LEG_WHERE, reason, text)))

    def test_unquoted_typed_leg_values_keep_their_refusals(self) -> None:
        self.assertEqual(_leg_outcome("1.5"), ("refused", UNQUOTED_FORM_MESSAGE.format(
            value="1.5", form="float")))
        self.assertEqual(_leg_outcome("null"), ("refused", UNQUOTED_FORM_MESSAGE.format(
            value="null", form="null")))
        # every YAML form of the refusal list is still read as itself when written quoted
        self.assertEqual(_leg_outcome("'1.5'"), ("value", "1.5"))
        self.assertEqual(_leg_outcome("pre-x"), ("value", "pre-x"))

    def test_matrix_axes_are_refused(self) -> None:
        for lines, text in (
                (["      matrix:", "        cargo_debug: [0, 1]"], "cargo_debug: [0, 1]"),
                (["      matrix:", "        cargo_debug:", "          - 0"], "cargo_debug:"),
                (["      matrix:", "        exclude:", "          - os: a"], "exclude:"),
                (["      matrix:", "        include:", "          - target: t",
                  "        cargo_debug: [0, 1]"], "cargo_debug: [0, 1]"),
                (["      matrix:", "        os: [a, b]", "        include:",
                  "          - target: t"], "os: [a, b]")):
            with self.subTest(text=text, lines=lines):
                job = Job("j", ["    runs-on: x", "    strategy:", *lines])
                with self.assertRaises(AssertionError) as caught:
                    _matrix_include(job)
                self.assertEqual(str(caught.exception),
                                 _unread("j: strategy.matrix", R_AXIS, text))

    def test_matrix_and_include_written_as_expressions_are_refused(self) -> None:
        cases = (
            (["    strategy: ${{ fromJSON(x) }}"], "j: strategy", R_STRATEGY_BLOCK,
             "${{ fromJSON(x) }}"),
            (["    strategy:", "      matrix: ${{ fromJSON(x) }}"], "j: strategy.matrix",
             R_MATRIX_BLOCK, "${{ fromJSON(x) }}"),
            (["    strategy:", "      matrix: {include: []}"], "j: strategy.matrix",
             R_MATRIX_BLOCK, "{include: []}"),
            (["    strategy:", "      matrix:", "        include: ${{ fromJSON(x) }}"],
             "j: strategy.matrix.include", R_INCLUDE_BLOCK, "${{ fromJSON(x) }}"),
            (["    strategy:", "      matrix:", "        include: [{a: 1}]"],
             "j: strategy.matrix.include", R_INCLUDE_BLOCK, "[{a: 1}]"),
            (["    strategy:", "      matrix:", "        include:"],
             "j: strategy.matrix.include", R_INCLUDE_BLOCK, ""),
            (["    strategy:", "      timeout: 3"], "j: strategy", R_STRATEGY_KEY, "timeout: 3"),
            (["    strategy:", "      matrix:", "        include:", "          - {t: 1}"],
             "j: strategy.matrix.include[0]", R_FLOW_MAPPING, "{t: 1}"),
        )
        for lines, where, reason, text in cases:
            with self.subTest(reason=reason, text=text):
                job = Job("j", ["    runs-on: x", *lines])
                with self.assertRaises(AssertionError) as caught:
                    _matrix_include(job)
                self.assertEqual(str(caught.exception), _unread(where, reason, text))

    def test_real_strategy_shapes_are_read_exactly(self) -> None:
        job = Job("j", ["    runs-on: x", "    strategy:", "      fail-fast: false",
                        "      max-parallel: 4", "      matrix:", "        include:",
                        "          - leg: ubuntu-latest,sqlite", "            node: n  # note",
                        "            shared_target: true", "            cargo_debug: '0'",
                        "            timeout: 95", "          - target: t",
                        "            runner: '[\"self-hosted\",\"linux-fed\"]'"])
        legs = _matrix_include(job)
        self.assertEqual(legs, [{"leg": "ubuntu-latest,sqlite", "node": "n",
                                 "shared_target": True, "cargo_debug": "0", "timeout": "95"},
                                {"target": "t", "runner": '["self-hosted","linux-fed"]'}])
        self.assertEqual([type(v) for v in legs[0].values()], [str, str, bool, QuotedStr, str])
        self.assertEqual(_matrix_include(Job("j", ["    runs-on: x"])), [])

    def test_leg_structure_refusals(self) -> None:
        entry = "          - target: t"
        cases = (
            ([entry, "           cargo_debug: 1"], "j: strategy.matrix.include[0]", R_INDENT,
             "cargo_debug: 1"),
            ([entry, "            cargo_debug:", "              deep: 1"],
             "j: strategy.matrix.include[0].cargo_debug", R_NESTED, "deep: 1"),
            ([entry, "            cargo_debug: abc", "              def"],
             "j: strategy.matrix.include[0].cargo_debug", R_NESTED, "def"),
            ([entry, "            target: u"], "j: strategy.matrix.include[0].target", R_DUPLICATE,
             "u"),
            ([entry, "            'a': 1"], "j: strategy.matrix.include[0]", R_LINE, "'a': 1"),
            ([entry, "            cargo_debug:1"], "j: strategy.matrix.include[0]", R_LINE,
             "cargo_debug:1"),
            ([entry, "            just text"], "j: strategy.matrix.include[0]", R_LINE,
             "just text"),
            (["          - 'a': 1"], "j: strategy.matrix.include[0]", R_LINE, "'a': 1"),
            (["          -", "            target: t"], "j: strategy.matrix.include[0]",
             R_BARE_DASH, "-"),
            ([entry, "          - target: u", "            cargo_debug: *d"],
             "j: strategy.matrix.include[1].cargo_debug", R_ALIAS, "*d"),
        )
        for lines, where, reason, text in cases:
            with self.subTest(reason=reason, text=text):
                with self.assertRaises(AssertionError) as caught:
                    _matrix_include(_leg_job(*lines))
                self.assertEqual(str(caught.exception), _unread(where, reason, text))

    def test_every_refusal_is_reported_naming_workflow_and_job(self) -> None:
        sites_of = ReachableWorkflowSites9681R3()._sites
        cases = (
            ("      matrix:\n        cargo_debug: [0, 1]\n", "w.yml: m: strategy.matrix: unread "
             "YAML form, matrix axis: 'cargo_debug: [0, 1]'"),
            ("      matrix:\n        include:\n          - {t: 1}\n", "w.yml: m: "
             "strategy.matrix.include[0]: unread YAML form, flow mapping: '{t: 1}'"),
            ("      matrix: ${{ fromJSON(x) }}\n", "w.yml: m: strategy.matrix: unread YAML form, "
             "matrix is not a block mapping: '${{ fromJSON(x) }}'"),
            ("      matrix:\n        include: ${{ fromJSON(x) }}\n", "w.yml: m: "
             "strategy.matrix.include: unread YAML form, include is not a block list: "
             "'${{ fromJSON(x) }}'"),
            ("      matrix:\n        include:\n          - target: t\n"
             "            cargo_debug: '0' # c\n            os: *d\n", "w.yml: m: "
             "strategy.matrix.include[0].os: unread YAML form, alias: '*d'"),
        )
        for strategy, problem in cases:
            with self.subTest(problem=problem):
                job = f"  m:\n    runs-on: ubuntu-latest\n    strategy:\n{strategy}    steps:\n" \
                      + STUB_CACHE_STEP
                sites, problems = sites_of({"w.yml": _stub_workflow("pull_request", job)})
                self.assertEqual((sites, problems), ({}, [problem]))


# Env values: `CARGO_X: <text>` read through Job.env() and _effective_key_env.
ENV_NAME = "CARGO_X"
ENV_EXPRESSION = "${{ matrix.cargo_debug || 'x' }}"
ENV_VALUE_ROWS: tuple[tuple[str, dict[str, object], dict[str, str]], ...] = (
    ("abc", {}, {ENV_NAME: "abc"}),
    ("'abc'", {}, {ENV_NAME: "abc"}),
    ('"abc"', {}, {ENV_NAME: "abc"}),
    ("abc # c", {}, {ENV_NAME: "abc"}),
    ("'abc' # c", {}, {ENV_NAME: "abc"}),
    ('"abc"   # c', {}, {ENV_NAME: "abc"}),
    ("'it''s'", {}, {ENV_NAME: "it's"}),
    ("-C link-arg=-fuse-ld=mold", {}, {ENV_NAME: "-C link-arg=-fuse-ld=mold"}),
    ('"-C link-arg=-fuse-ld=mold"', {}, {ENV_NAME: "-C link-arg=-fuse-ld=mold"}),
    ("0", {}, {ENV_NAME: "0"}),
    ("'0'", {}, {ENV_NAME: "0"}),
    ('"0"', {}, {ENV_NAME: "0"}),
    ("10", {}, {ENV_NAME: "10"}),
    ('"false"', {}, {ENV_NAME: "false"}),
    ("", {}, {}),
    ("''", {}, {}),
    ("# only a comment", {}, {}),
    (ENV_EXPRESSION, {}, {ENV_NAME: "x"}),
    (ENV_EXPRESSION + " # c", {}, {ENV_NAME: "x"}),
    ('"' + ENV_EXPRESSION + '"', {}, {ENV_NAME: "x"}),
    ("'${{ matrix.cargo_debug || ''x'' }}'", {}, {ENV_NAME: "x"}),
    (ENV_EXPRESSION, {"cargo_debug": QuotedStr("1")}, {ENV_NAME: "1"}),
)
ENV_REFUSED_ROWS: tuple[tuple[str, str], ...] = (
    ("*d", R_ALIAS), ("&d 0", R_ANCHOR), ("!!str 0", R_TAG), ("[0]", R_FLOW_SEQUENCE),
    ("{a: 1}", R_FLOW_MAPPING), (">-", R_BLOCK_SCALAR), ("|", R_BLOCK_SCALAR),
    ("'a' b", R_AFTER_QUOTE), ("'a", R_UNTERMINATED), ('"a\\n"', R_ESCAPE),
    ("a: b", R_COLON), ("@x", R_RESERVED), ("- x", R_BLOCK_INDICATOR),
    ("1.5", "unquoted YAML float"), ("null", "unquoted YAML null"), ("~", "unquoted YAML null"),
    ("true", "unquoted YAML boolean"), ("0x1F", "unquoted YAML integer"),
    ("01", "unquoted YAML integer"),
)


def _env_outcome(text: str, leg: dict[str, object], *more: str) -> tuple[str, object]:
    job = Job("j", ["    env:", f"      {ENV_NAME}: {text}", *more])
    try:
        return "value", _effective_key_env(job.env(), leg)
    except AssertionError as exc:
        return "refused", str(exc)


class UnreadEnvForms9745R1(unittest.TestCase):
    """#9745 r1 L2 (env side): an env value is its decoded text or an expression this module
    evaluates; any other form is refused naming the env var and the form."""

    def test_env_values_evaluate_exactly(self) -> None:
        for text, leg, want in ENV_VALUE_ROWS:
            with self.subTest(text=text, leg=leg):
                self.assertEqual(_env_outcome(text, leg), ("value", want))

    def test_unread_env_forms_are_refused_by_name(self) -> None:
        for text, reason in ENV_REFUSED_ROWS:
            with self.subTest(text=text):
                self.assertEqual(_env_outcome(text, {}), (
                    "refused", _unread(ENV_NAME, reason, text.strip())))

    def test_other_expressions_keep_their_refusals(self) -> None:
        for text in ("${{ inputs.d }}", "pre-" + ENV_EXPRESSION, "'${{ inputs.d }}'",
                     "${{ matrix.a || 'x' }} tail"):
            with self.subTest(text=text):
                kind, message = _env_outcome(text, {})
                self.assertEqual(kind, "refused")
                self.assertTrue(message.startswith(
                    f"{ENV_NAME}: unrecognised expression form in an env value: "), message)

    def test_nested_and_continued_env_values_are_refused(self) -> None:
        self.assertEqual(_env_outcome("", {}, "        a: 1"), (
            "refused", _unread(ENV_NAME, R_NESTED, "a: 1")))
        self.assertEqual(_env_outcome("abc", {}, "        def"), (
            "refused", _unread(ENV_NAME, R_NESTED, "def")))
        self.assertEqual(_env_outcome("abc", {}, "      OTHER: 1"), ("value", {ENV_NAME: "abc"}))

    def test_a_matrix_read_by_an_env_must_be_exact_end_to_end(self) -> None:
        # The leg a real job gives and the env text it reads, together.
        job = _leg_job("          - target: t", "            cargo_debug: '0' # off")
        (leg,) = _matrix_include(job)
        self.assertEqual(_effective_key_env({ENV_NAME: ENV_EXPRESSION}, leg), {ENV_NAME: "0"})
        job = _leg_job("          - target: t", "            cargo_debug: 'it''s'")
        (leg,) = _matrix_include(job)
        self.assertEqual(_effective_key_env({ENV_NAME: ENV_EXPRESSION}, leg), {ENV_NAME: "it's"})


# ---------------------------------------------------------------------------------------------
# #9770: whole-step and job-level mirror comparison of every PAIRS row.
# For every PAIRS row the whole rust-cache step and each mirrored cargo step on both sides are
# compared against a HAND-WRITTEN table with a closed allowed-difference list. Every step key and
# every job-level key is compared; a key the table does not allow to differ must be equal on both
# sides, and a key outside the known sets fails naming workflow, job, step and key. The expected
# column below is written by hand from the workflow files and never derived from their text.
# ---------------------------------------------------------------------------------------------
class _Any:
    """Marks a value the hand table lets differ without pinning it."""

    def __repr__(self) -> str:
        return "ANY"


ANY = _Any()
Expected = object  # a str, None (the key is absent) or ANY
KNOWN_STEP_KEYS = ("id", "name", "if", "uses", "with", "env", "run", "shell", "working-directory",
                   "continue-on-error", "timeout-minutes")
KNOWN_JOB_KEYS = ("name", "needs", "if", "permissions", "runs-on", "timeout-minutes", "strategy",
                  "defaults", "container", "services", "concurrency", "outputs", "environment",
                  "continue-on-error")
JOB_KEYS_COMPARED_ELSEWHERE = ("steps", "env")
ONE_SIDED_PR = "pr"
ONE_SIDED_WARM = "warm"


@dataclass(frozen=True)
class Row:
    """One mirrored step: its identity on the PR side and on the warm side, and the keys that may
    differ as (PR value, warm value); a value of None means the key is absent."""

    pr_id: str
    warm_id: str
    allowed: dict[str, tuple[object, object]] = field(default_factory=dict)


@dataclass(frozen=True)
class PairTable:
    rows: tuple[Row, ...]
    pr_only: tuple[str, ...]
    job_allowed: dict[str, tuple[object, object]]
    env_one_sided: dict[str, str]

    def row_for(self, pr_id: str) -> Row:
        for row in self.rows:
            if row.pr_id == pr_id:
                return row
        raise KeyError(pr_id)


# #9821 (I5): every PR-side work step also carries the LEG_SKIP guard; the rows are written out.
CI_IF_RUNS = "needs.classify.outputs.cargo_skip != 'true' && env.LEG_SKIP != 'true'"
CI_IF_HOSTED = ("needs.classify.outputs.cargo_skip != 'true' && runner.environment == "
                "'github-hosted' && env.LEG_SKIP != 'true'")
CI_IF_LOW_MEM = ("needs.classify.outputs.cargo_skip != 'true' && matrix.leg == "
                 "'ubuntu-latest,sqlite' && env.LEG_SKIP != 'true'")
WARM_IF_CACHE_MISS = "steps.rust-cache.outputs.cache-hit != 'true'"
WARM_CACHE_ID = "rust-cache"
WARM_CACHE_NAME = "Rust cache (write the key the PR job restores)"
CI_CARGO_ENV = "\n".join((
    'AI_MEMORY_NO_CONFIG: "1"',
    "TIER: sqlite",
    "CI_NODE: ubuntu-latest",
    "TEST_IMPACT: ${{ needs.classify.outputs.test_impact }}",
    "DOCS_ONLY: ${{ needs.classify.outputs.docs_only }}",
    "TEST_IMPACT_REASON: ${{ needs.classify.outputs.test_impact_reason }}",
    "TEST_IMPACT_COUNT: ${{ needs.classify.outputs.test_impact_count }}",
    "TEST_IMPACT_TOTAL: ${{ needs.classify.outputs.test_impact_total }}",
    "JOB_TIMEOUT_MIN: 95",
    "CI_PG_ISOLATE_OFF: ${{ vars.CI_PG_ISOLATE_OFF }}",
    "HOST_SEMAPHORE_SLOTS: ${{ matrix.node == 'linux-fed' && matrix.tier == 'enterprise-fed' "
    "&& '2' || '0' }}",
    "HOST_SEMAPHORE_MAX_WAIT_SECS: '3600'",
))
CI_RUST_CACHE_ALLOWED = {"if": (CI_IF_HOSTED, None), "id": (None, WARM_CACHE_ID),
                         "name": (None, WARM_CACHE_NAME)}
COV_RUST_CACHE_ALLOWED = {"id": (None, WARM_CACHE_ID), "name": (None, WARM_CACHE_NAME)}

PAIR_TABLES: dict[tuple[str, str], PairTable] = {
    ("ci.yml", "check"): PairTable(
        rows=(
            Row("actions/checkout", "actions/checkout"),
            Row("Free disk before tests (hosted image only,",
                "Free disk before tests (hosted image only,", {"if": (CI_IF_HOSTED, None)}),
            Row("actions/setup-python", "actions/setup-python", {"if": (CI_IF_HOSTED, None)}),
            Row("actions/setup-node", "actions/setup-node", {"if": (CI_IF_HOSTED, None)}),
            Row("Install Rust 1.99.1 (matches rust-toolchain.toml pin)",
                "Install Rust 1.99.1 (matches rust-toolchain.toml pin)",
                {"if": (CI_IF_RUNS, None)}),
            Row(RUST_CACHE, RUST_CACHE, CI_RUST_CACHE_ALLOWED),
            Row("Low-mem hosted sqlite link (debuginfo=0, system ld — mold isolation)",
                "Low-mem hosted sqlite link (debuginfo=0, system ld — mold isolation)",
                {"if": (CI_IF_LOW_MEM, None)}),
            Row("Run tests (impact-aware)", "Build the test targets (no run)", {
                "name": (ANY, ANY), "run": (ANY, ANY), "shell": ("bash", None),
                "if": (CI_IF_RUNS, WARM_IF_CACHE_MISS), "env": (CI_CARGO_ENV, None)}),
        ),
        pr_only=(
            "Record job start (#6795)",
            "Fork-PR refusal (self-hosted legs never run fork code)",
            "Draft skip (#9821)",
            "Prune stale runner TMPDIR (#8634)",
            "cargo_skip short-circuit",
            "Per-runner cargo target (#7188)",
            "sccache build cache (#7199)",
            "Ensure python3 + node present (self-hosted;",
            "Assert rustup is provisioned (self-hosted; fail-closed",
            "Prebuild t0 orchestrator (macOS e1 anti-flake,",
            "Configure enterprise-fed tier (per-job ephemeral db, enterprise-fed legs only)",
            "Run the pg_isolated_binary live cells (enterprise-fed legs only)",
            "Scrub inherited passphrase env (self-hosted only, issue 3539 hygiene)",
            "Load gate (#6795)",
            "Upload test results (durable audit history)",
            "Upload shard logs (#6344)",
            "Upload isolated-lane per-binary logs (#6383)",
            "Trim target/debug before the cache save (hosted)",
            "Cleanup enterprise-fed ephemeral db",
            "sccache hit-rate summary (#7199)",
            "sccache stop CI server (#7199)",
            "Prune stale runner artifacts (#7188)",
            "Sweep target/debug to the size cap (self-hosted)",
            "Sweep per-runner cargo target to the size cap (self-hosted,",
        ),
        job_allowed={
            "name": (ANY, ANY), "needs": ("classify", None), "strategy": (ANY, None),
            "runs-on": ('["ubuntu-latest"]', "ubuntu-latest"),
        },
        env_one_sided={"SELF_HOSTED_TARGET_CAP_BYTES": ONE_SIDED_PR,
                       "LEG_SKIP": ONE_SIDED_PR},
    ),
    ("coverage.yml", "per-module-thresholds"): PairTable(
        rows=(
            Row("actions/checkout", "actions/checkout"),
            Row("Free disk + add swap (#1148 belt-and-suspenders, aggressive)",
                "Free disk + add swap (#1148 belt-and-suspenders, aggressive)"),
            Row("Install Rust 1.99.1", "Install Rust 1.99.1"),
            Row("Install mold linker (#1148, pinned+bounded",
                "Install mold linker (#1148, pinned+bounded"),
            Row(RUST_CACHE, RUST_CACHE, COV_RUST_CACHE_ALLOWED),
            Row("Restore HuggingFace models (#2019)", "Restore HuggingFace models (#2019)"),
            Row("Pre-stage HF models with retry (#2019)", "Pre-stage HF models with retry (#2019)"),
            Row("Verify staged HF cache is hf-hub-resolvable (#2019)",
                "Verify staged HF cache is hf-hub-resolvable (#2019)"),
            Row("Save HuggingFace models (#2019, push only)",
                "Save HuggingFace models (#2019, push only)"),
            Row("Install cargo-llvm-cov", "Install cargo-llvm-cov",
                {"if": (None, WARM_IF_CACHE_MISS)}),
            Row("Generate coverage JSON",
                "Build the instrumented coverage targets (no test runs)", {
                    "name": (ANY, ANY), "run": (ANY, ANY), "if": (None, WARM_IF_CACHE_MISS),
                    "env": (None, None), "id": ("sweep", None)}),
        ),
        pr_only=(
            "Install jq + postgresql-client (bounded+retry",
            "Start TLS PostgreSQL + AGE (#3705)",
            "Install pgvector + provision AGE/vector extensions",
            "PostgreSQL package repair + preflight (#9235)",
            "Record the coverage sweep start (#9263)",
            "Record the coverage sweep end (#9263)",
            "Name the coverage sweep end (#9263)",
            "Enforce per-module thresholds",
            "Render coverage comment body (#1993)",
            "Post coverage to PR (sticky) (#1993)",
            "Upload coverage JSON",
        ),
        job_allowed={
            "name": (ANY, ANY), "needs": ("classify", None),
            "if": ("needs.classify.outputs.cargo_skip != 'true'", None),
            "permissions": ("contents: read\npull-requests: write", None),
        },
        env_one_sided={},
    ),
}


def _step_ident(step: Step) -> str:
    """The identity a hand-table row names: the action for a rust-cache step, else the step label."""
    return RUST_CACHE if step.uses_name() == RUST_CACHE else step.label()


def _relative(lines: list[str], indent: int) -> str:
    """The non-comment lines of a block with `indent` columns taken off, joined by newlines."""
    out = []
    for line in lines:
        if _is_comment_or_blank(line):
            continue
        out.append(line.rstrip()[indent:] if _indent(line) >= indent else line.strip())
    return "\n".join(out)


def _step_value(step: Step, key: str, leg: dict[str, object]) -> str | None:
    """One step key as text (a matrix reference of `leg` expanded), or None when absent."""
    if key == "run":
        value: str | None = step.run() if "run" in step.blocks else None
    elif step.keys.get(key) is not None:
        value = step.keys[key]
        more = _relative(step.blocks.get(key, []), KEY_INDENT + 2)
        if more:
            value += "\n" + more
    elif key in step.blocks:
        value = _relative(step.blocks[key], KEY_INDENT + 2) or None
    else:
        return None
    return None if value is None else _expand_matrix(value, leg)


def _job_value(job: Job, key: str, leg: dict[str, object]) -> str | None:
    value = _relative(job.block(key), 6)
    return _expand_matrix(value, leg) if value else None


def _job_keys(job: Job) -> list[str]:
    keys = [line.strip().partition(":")[0] for line in job.lines
            if _indent(line) == 4 and not _is_comment_or_blank(line)
            and not line.lstrip().startswith("- ")]
    return list(dict.fromkeys(keys))


def _side_steps(wf: Workflow, job_id: str, known: set[str], problems: list[str]) -> dict[str, Step]:
    """The steps of one job by identity; a duplicate or an unmapped step is a problem."""
    found: dict[str, list[Step]] = {}
    for step in wf.jobs()[job_id].steps():
        found.setdefault(_step_ident(step), []).append(step)
    out: dict[str, Step] = {}
    for ident, steps in found.items():
        if len(steps) > 1:
            problems.append(f"{wf.name}:{job_id}: step {ident!r} appears {len(steps)} times")
        if ident not in known:
            problems.append(f"{wf.name}:{job_id} step {ident!r}: no row in the mirror table")
        out[ident] = steps[0]
    return out


def _table_problem(where: str, key_text: str, key: str, actual: object, expected: object) -> str:
    return f"{where}: {key_text} {key!r} is {actual!r}, the hand table says {expected!r}"


def _compare_key(key: str, pr_value: str | None, warm_value: str | None,
                 allowed: dict[str, tuple[object, object]], pr_where: str, warm_where: str,
                 key_text: str, differs: str, problems: list[str]) -> None:
    """One key: pinned to the hand table when it may differ, equal on both sides when not."""
    if key in allowed:
        for actual, expected, where in ((pr_value, allowed[key][0], pr_where),
                                        (warm_value, allowed[key][1], warm_where)):
            if expected is not ANY and actual != expected:
                problems.append(_table_problem(where, key_text, key, actual, expected))
    elif pr_value != warm_value:
        problems.append(differs.format(key=key, pv=pr_value, wv=warm_value))


def _step_problems(pr_wf: Workflow, pr_job_id: str, warm_wf: Workflow, warm_job_id: str,
                   table: PairTable, leg: dict[str, object]) -> list[str]:
    problems: list[str] = []
    pr_steps = _side_steps(pr_wf, pr_job_id,
                           {row.pr_id for row in table.rows} | set(table.pr_only), problems)
    warm_steps = _side_steps(warm_wf, warm_job_id, {row.warm_id for row in table.rows}, problems)
    for row in table.rows:
        for wf_name, job_id, steps, ident in ((pr_wf.name, pr_job_id, pr_steps, row.pr_id),
                                              (warm_wf.name, warm_job_id, warm_steps, row.warm_id)):
            if ident not in steps:
                problems.append(f"{wf_name}:{job_id}: no step {ident!r} "
                                "(the mirror table needs it)")
        if row.pr_id not in pr_steps or row.warm_id not in warm_steps:
            continue
        pr_step, warm_step = pr_steps[row.pr_id], warm_steps[row.warm_id]
        for wf_name, job_id, step, ident in ((pr_wf.name, pr_job_id, pr_step, row.pr_id),
                                             (warm_wf.name, warm_job_id, warm_step, row.warm_id)):
            for key in dict.fromkeys([*step.blocks, *step.keys]):
                if key not in KNOWN_STEP_KEYS:
                    problems.append(f"{wf_name}:{job_id} step {ident!r}: step key {key!r} is not "
                                    "a known step key")
        differs = (f"{pr_wf.name}:{pr_job_id} step {row.pr_id!r} vs {warm_wf.name}:{warm_job_id} "
                   f"step {row.warm_id!r}: key {{key!r}} differs: {pr_wf.name} has {{pv!r}}, "
                   f"{warm_wf.name} has {{wv!r}}")
        for key in KNOWN_STEP_KEYS:
            _compare_key(key, _step_value(pr_step, key, leg), _step_value(warm_step, key, {}),
                         row.allowed, f"{pr_wf.name}:{pr_job_id} step {row.pr_id!r}",
                         f"{warm_wf.name}:{warm_job_id} step {row.warm_id!r}", "key", differs,
                         problems)
    return problems


def _job_problems(pr_wf: Workflow, pr_job_id: str, warm_wf: Workflow, warm_job_id: str,
                  table: PairTable, leg: dict[str, object]) -> list[str]:
    problems: list[str] = []
    pr_job, warm_job = pr_wf.jobs()[pr_job_id], warm_wf.jobs()[warm_job_id]
    for wf_name, job in ((pr_wf.name, pr_job), (warm_wf.name, warm_job)):
        for key in _job_keys(job):
            if key not in (*KNOWN_JOB_KEYS, *JOB_KEYS_COMPARED_ELSEWHERE):
                problems.append(f"{wf_name}:{job.job_id}: job key {key!r} is not a known job key")
    differs = (f"{pr_wf.name}:{pr_job_id} vs {warm_wf.name}:{warm_job_id}: job key {{key!r}} "
               f"differs: {pr_wf.name} has {{pv!r}}, {warm_wf.name} has {{wv!r}}")
    for key in KNOWN_JOB_KEYS:
        values: list[str | None] = []
        for wf_name, job_id, job, side_leg in ((pr_wf.name, pr_job_id, pr_job, leg),
                                               (warm_wf.name, warm_job_id, warm_job, {})):
            try:
                values.append(_runs_on(job, side_leg) if key == "runs-on"
                              else _job_value(job, key, side_leg))
            except AssertionError as exc:
                problems.append(f"{wf_name}:{job_id}: {key} cannot be read: {exc}")
        if len(values) == 2:  # a side that could not be read is reported, never compared
            _compare_key(key, values[0], values[1], table.job_allowed,
                         f"{pr_wf.name}:{pr_job_id}", f"{warm_wf.name}:{warm_job_id}", "job key",
                         differs, problems)
    return problems


def _effective_env(wf: Workflow, job_id: str, dropped: set[str]) -> dict[str, str]:
    env = {**wf.env(), **wf.jobs()[job_id].env()}
    return {name: raw for name, raw in env.items() if name not in dropped}


def _env_problems(pr_wf: Workflow, pr_job_id: str, warm_wf: Workflow, warm_job_id: str,
                  table: PairTable, leg: dict[str, object]) -> list[str]:
    problems: list[str] = []
    pr_env = _effective_env(pr_wf, pr_job_id,
                            {n for n, side in table.env_one_sided.items() if side == ONE_SIDED_PR})
    warm_env = _effective_env(warm_wf, warm_job_id,
                              {n for n, side in table.env_one_sided.items()
                               if side == ONE_SIDED_WARM})
    for name in dict.fromkeys([*pr_env, *warm_env]):
        values: list[str | None] = []
        for wf_name, job_id, env, side_leg in ((pr_wf.name, pr_job_id, pr_env, leg),
                                               (warm_wf.name, warm_job_id, warm_env, {})):
            try:
                values.append(_effective_env_value(name, env[name], side_leg)
                              if name in env else None)
            except AssertionError as exc:
                problems.append(f"{wf_name}:{job_id}: env {name!r} cannot be evaluated: {exc}")
        if len(values) == 2 and values[0] != values[1]:  # a failed side is never compared
            problems.append(f"{pr_wf.name}:{pr_job_id} vs {warm_wf.name}:{warm_job_id}: env "
                            f"{name!r} differs: {pr_wf.name} has {values[0]!r}, "
                            f"{warm_wf.name} has {values[1]!r}")
    return problems


def pair_mirror_problems(pr_wf: Workflow, pr_job_id: str, warm_wf: Workflow, warm_job_id: str,
                         leg: dict[str, object]) -> list[str]:
    """Every difference between a PR job and its warm job that the hand table does not allow."""
    table = PAIR_TABLES[(pr_wf.name, pr_job_id)]
    problems = _step_problems(pr_wf, pr_job_id, warm_wf, warm_job_id, table, leg)
    problems.extend(_job_problems(pr_wf, pr_job_id, warm_wf, warm_job_id, table, leg))
    problems.extend(_env_problems(pr_wf, pr_job_id, warm_wf, warm_job_id, table, leg))
    pr_defaults = _relative(pr_wf.top("defaults"), 2) or None
    warm_defaults = _relative(warm_wf.top("defaults"), 2) or None
    if pr_defaults != warm_defaults:
        problems.append(f"{pr_wf.name} vs {warm_wf.name}: workflow key 'defaults' differs: "
                        f"{pr_wf.name} has {pr_defaults!r}, {warm_wf.name} has {warm_defaults!r}")
    return problems


# ---------------------------------------------------------------------------------------------
# #9770: whole-step and job-level mirror comparison of every PAIRS row (fixtures).
# Each fixture feeds `pair_mirror_problems` a mutated copy of the real workflow text and asserts
# the exact refusal. The hand tables (`PAIR_TABLES`) are written by hand in the module above.
# ---------------------------------------------------------------------------------------------
FIXTURE_ENV_NAME = "FOO"
FIXTURE_ENV_VALUE = "bar"
FIXTURE_ENV_BLOCK = f"{FIXTURE_ENV_NAME}: {FIXTURE_ENV_VALUE}"
FIXTURE_EXTRA_STEP = "Extra step 9770"
# Hand-written per pair: (PR cargo step, warm cargo step, a mirrored disk step, a mirrored run step).
PAIR_STEP_NAMES_9770 = {
    "ci.yml": ("Run tests (impact-aware)", "Build the test targets (no run)",
               "Free disk before tests (hosted image only,",
               "Install Rust 1.99.1 (matches rust-toolchain.toml pin)"),
    "coverage.yml": ("Generate coverage JSON", "Build the instrumented coverage targets (no test runs)",
                     "Free disk + add swap (#1148 belt-and-suspenders, aggressive)",
                     "Install Rust 1.99.1"),
}
UNPINNED_ABSENT_STEP_KEYS = ("working-directory", "continue-on-error", "timeout-minutes")
UNPINNED_ABSENT_JOB_KEYS = ("services", "concurrency", "outputs", "environment", "continue-on-error")
SIDES_9770 = ("pr", "warm")
# Hand-written per PR workflow: the "<workflow>:<job>" label of its PR side and of its warm side.
SIDE_LABELS_9770 = {
    "ci.yml": ("ci.yml:check", "rust-cache-warm.yml:check-hosted-sqlite"),
    "coverage.yml": ("coverage.yml:per-module-thresholds", "rust-cache-warm.yml:coverage"),
}
# Hand-written: what `_runs_on` says when a runs-on reads `matrix.zz` that the leg does not set.
# PR side (job id, leg id) and warm side (job id, leg ''), per PR workflow.
RUNS_ON_TAIL_9770 = {
    ("ci.yml", "pr"): "check: runs-on reads matrix.zz, which leg 'leg=ubuntu-latest,sqlite' "
                      "does not set",
    ("ci.yml", "warm"): "check-hosted-sqlite: runs-on reads matrix.zz, which leg '' does not set",
    ("coverage.yml", "pr"): "per-module-thresholds: runs-on reads matrix.zz, which leg '' "
                            "does not set",
    ("coverage.yml", "warm"): "coverage: runs-on reads matrix.zz, which leg '' does not set",
}
UNEVALUABLE_ENV_9770 = "FOO: ${{ weird }}"
UNEVALUABLE_ENV_TAIL_9770 = ("env 'FOO' cannot be evaluated: FOO: unrecognised expression form "
                             "in an env value: '${{ weird }}'")
NODE_MARK_9770 = "@NODE@"
# Hand-written: the real `env` block of the PR cargo step of ci.yml (CI_NODE is the one line the
# test changes); the hand table pins it with CI_NODE taken as 'ubuntu-latest'.
CI_CARGO_ENV_9770 = "\n".join((
    'AI_MEMORY_NO_CONFIG: "1"',
    "TIER: sqlite",
    "CI_NODE: " + NODE_MARK_9770,
    "TEST_IMPACT: ${{ needs.classify.outputs.test_impact }}",
    "DOCS_ONLY: ${{ needs.classify.outputs.docs_only }}",
    "TEST_IMPACT_REASON: ${{ needs.classify.outputs.test_impact_reason }}",
    "TEST_IMPACT_COUNT: ${{ needs.classify.outputs.test_impact_count }}",
    "TEST_IMPACT_TOTAL: ${{ needs.classify.outputs.test_impact_total }}",
    "JOB_TIMEOUT_MIN: 95",
    "CI_PG_ISOLATE_OFF: ${{ vars.CI_PG_ISOLATE_OFF }}",
    "HOST_SEMAPHORE_SLOTS: ${{ matrix.node == 'linux-fed' && matrix.tier == 'enterprise-fed' "
    "&& '2' || '0' }}",
    "HOST_SEMAPHORE_MAX_WAIT_SECS: '3600'",
))


def _job_range_9770(lines: list[str], job_id: str) -> tuple[int, int]:
    jobs_at = next(i for i, line in enumerate(lines) if line.startswith("jobs:"))
    starts = [i for i in range(jobs_at + 1, len(lines)) if lines[i].rstrip() == f"  {job_id}:"]
    if len(starts) != 1:
        raise AssertionError(f"fixture: job {job_id!r} found {len(starts)} times")
    end = len(lines)
    for i in range(starts[0] + 1, len(lines)):
        if lines[i].strip() and not lines[i].lstrip().startswith("#") and _indent(lines[i]) <= 2:
            end = i
            break
    return starts[0], end


def _step_range_9770(lines: list[str], job_id: str, ident: str) -> tuple[int, int]:
    start, end = _job_range_9770(lines, job_id)
    steps_at = next(i for i in range(start, end) if lines[i].rstrip() == "    steps:")
    bounds = [i for i in range(steps_at + 1, end)
              if _indent(lines[i]) == STEP_INDENT and lines[i].lstrip().startswith("- ")]
    found = []
    for n, first in enumerate(bounds):
        stop = bounds[n + 1] if n + 1 < len(bounds) else end
        if _step_ident(_parse_step(lines[first:stop])) == ident:
            found.append((first, stop))
    if len(found) != 1:
        raise AssertionError(f"fixture: step {ident!r} found {len(found)} times in {job_id!r}")
    return found[0]


def _on_step_9770(wf: Workflow, job_id: str, ident: str,
                  edit: Callable[[list[str]], list[str]]) -> Workflow:
    lines = list(wf.lines)
    first, stop = _step_range_9770(lines, job_id, ident)
    return Workflow(wf.name, lines[:first] + edit(lines[first:stop]) + lines[stop:])


def _on_job_9770(wf: Workflow, job_id: str,
                 edit: Callable[[list[str]], list[str]]) -> Workflow:
    lines = list(wf.lines)
    start, end = _job_range_9770(lines, job_id)
    return Workflow(wf.name, lines[:start] + edit(lines[start:end]) + lines[end:])


def _key_lines_9770(indent: int, key: str, value: str | list[str]) -> list[str]:
    pad = " " * indent
    if isinstance(value, str):
        return [f"{pad}{key}: {value}"]
    return [f"{pad}{key}:", *[f"{pad}  {item}" for item in value]]


def _add_step_key_9770(key: str, value: str | list[str]) -> Callable[[list[str]], list[str]]:
    def edit(seg: list[str]) -> list[str]:
        step = _parse_step(seg)
        if key in step.keys or key in step.blocks:
            raise AssertionError(f"fixture: the step already has {key!r}")
        return [seg[0], *_key_lines_9770(KEY_INDENT, key, value), *seg[1:]]
    return edit


def _sub_in_lines_9770(old: str, new: str) -> Callable[[list[str]], list[str]]:
    def edit(seg: list[str]) -> list[str]:
        hits = [i for i, line in enumerate(seg) if old in line]
        if len(hits) != 1:
            raise AssertionError(f"fixture: {old!r} matched {len(hits)} lines")
        out = list(seg)
        out[hits[0]] = out[hits[0]].replace(old, new, 1)
        return out
    return edit


def _append_run_line_9770(seg: list[str]) -> list[str]:
    at = next((i for i, line in enumerate(seg)
               if _indent(line) == KEY_INDENT and line.strip().startswith("run:")), None)
    if at is None or seg[at].strip() != "run: |":
        raise AssertionError("fixture: the step has no block run")
    stop = len(seg)
    for i in range(at + 1, len(seg)):
        if seg[i].strip() and _indent(seg[i]) <= KEY_INDENT and not seg[i].lstrip().startswith("#"):
            stop = i
            break
    while stop > at + 1 and (not seg[stop - 1].strip() or (
            seg[stop - 1].lstrip().startswith("#") and _indent(seg[stop - 1]) <= KEY_INDENT)):
        stop -= 1
    return [*seg[:stop], " " * (KEY_INDENT + 2) + "echo mutated-9770", *seg[stop:]]


def _add_job_key_9770(key: str, value: str | list[str]) -> Callable[[list[str]], list[str]]:
    def edit(seg: list[str]) -> list[str]:
        if any(_indent(line) == 4 and line.strip().startswith(key + ":") for line in seg):
            raise AssertionError(f"fixture: the job already has {key!r}")
        return [seg[0], *_key_lines_9770(4, key, value), *seg[1:]]
    return edit


def _set_job_line_9770(key: str, value: str) -> Callable[[list[str]], list[str]]:
    def edit(seg: list[str]) -> list[str]:
        hits = [i for i, line in enumerate(seg)
                if _indent(line) == 4 and line.strip().startswith(key + ":")]
        if len(hits) != 1:
            raise AssertionError(f"fixture: job key {key!r} found {len(hits)} times")
        out = list(seg)
        out[hits[0]] = f"    {key}: {value}"
        return out
    return edit


def _add_env_9770(header_indent: int) -> Callable[[list[str]], list[str]]:
    def edit(seg: list[str]) -> list[str]:
        hits = [i for i, line in enumerate(seg)
                if _indent(line) == header_indent and line.strip() == "env:"]
        if len(hits) != 1:
            raise AssertionError(f"fixture: env block found {len(hits)} times")
        return [*seg[:hits[0] + 1], " " * (header_indent + 2) + FIXTURE_ENV_BLOCK,
                *seg[hits[0] + 1:]]
    return edit


def _add_step_9770(job_id: str, wf: Workflow) -> Workflow:
    lines = list(wf.lines)
    start, end = _job_range_9770(lines, job_id)
    last = max(i for i in range(start, end)
               if lines[i].strip() and not lines[i].lstrip().startswith("#"))
    new = [f"      - name: {FIXTURE_EXTRA_STEP}", "        run: echo extra"]
    return Workflow(wf.name, [*lines[:last + 1], *new, *lines[last + 1:]])


def _drop_step_9770(wf: Workflow, job_id: str, ident: str) -> Workflow:
    lines = list(wf.lines)
    first, stop = _step_range_9770(lines, job_id, ident)
    return Workflow(wf.name, lines[:first] + lines[stop:])


def _duplicate_step_9770(wf: Workflow, job_id: str, ident: str) -> Workflow:
    lines = list(wf.lines)
    first, stop = _step_range_9770(lines, job_id, ident)
    return Workflow(wf.name, lines[:stop] + lines[first:stop] + lines[stop:])


def _triplicate_step_9770(wf: Workflow, job_id: str, ident: str) -> Workflow:
    lines = list(wf.lines)
    first, stop = _step_range_9770(lines, job_id, ident)
    return Workflow(wf.name, lines[:stop] + lines[first:stop] * 2 + lines[stop:])


def _pair_problems_9770(pair: tuple[str, str, str, str], pr_wf: Workflow | None = None,
                        warm_wf: Workflow | None = None) -> list[str]:
    pr_name, pr_job_id, warm_job_id, _ = pair
    legs = _hosted_legs(Workflow.load(pr_name).jobs()[pr_job_id])
    pr_wf = pr_wf or Workflow.load(pr_name)
    warm_wf = warm_wf or Workflow.load(WARM)
    out: list[str] = []
    for leg in legs:
        out.extend(pair_mirror_problems(pr_wf, pr_job_id, warm_wf, warm_job_id, leg))
    return out


def _mutated_9770(pair: tuple[str, str, str, str], side: str,
                  edit: Callable[[Workflow, str], Workflow]) -> list[str]:
    """The problems after `edit(workflow, job_id)` rewrote the PR or the warm side of `pair`."""
    pr_name, pr_job_id, warm_job_id, _ = pair
    if side == "pr":
        return _pair_problems_9770(pair, pr_wf=edit(Workflow.load(pr_name), pr_job_id))
    return _pair_problems_9770(pair, warm_wf=edit(Workflow.load(WARM), warm_job_id))


def _differs_9770(pair: tuple[str, str, str, str], pr_id: str, warm_id: str, key: str,
                  pr_value: object, warm_value: object) -> str:
    return (f"{pair[0]}:{pair[1]} step {pr_id!r} vs {WARM}:{pair[2]} step {warm_id!r}: "
            f"key {key!r} differs: {pair[0]} has {pr_value!r}, {WARM} has {warm_value!r}")


def _table_9770(pair: tuple[str, str, str, str], side: str, ident: str, key: str,
                actual: object, expected: object) -> str:
    wf, job = (pair[0], pair[1]) if side == "pr" else (WARM, pair[2])
    return (f"{wf}:{job} step {ident!r}: key {key!r} is {actual!r}, "
            f"the hand table says {expected!r}")


def _side_ids_9770(pair: tuple[str, str, str, str], side: str) -> tuple[str, str]:
    """(workflow file, job id) of one side of a pair."""
    return (pair[0], pair[1]) if side == "pr" else (WARM, pair[2])


def _cache_edit_9770(side: str, pair: tuple[str, str, str, str],
                     edit: Callable[[list[str]], list[str]]) -> list[str]:
    return _mutated_9770(pair, side, lambda wf, job: _on_step_9770(wf, job, RUST_CACHE, edit))


def _both_sides_9770(pair: tuple[str, str, str, str], pr_edit: Callable[[Workflow, str], Workflow],
                     warm_edit: Callable[[Workflow, str], Workflow]) -> list[str]:
    """The problems after one edit on the PR side and one on the warm side of `pair`."""
    pr_name, pr_job_id, warm_job_id, _ = pair
    return _pair_problems_9770(pair, pr_wf=pr_edit(Workflow.load(pr_name), pr_job_id),
                               warm_wf=warm_edit(Workflow.load(WARM), warm_job_id))


def _keep_9770(wf: Workflow, job_id: str) -> Workflow:
    return wf


def _runs_on_unread_9770(wf: Workflow, job_id: str) -> Workflow:
    return _on_job_9770(wf, job_id, _set_job_line_9770("runs-on", "${{ matrix.zz }}"))


def _env_edit_9770(entry: str) -> Callable[[Workflow, str], Workflow]:
    def edit(wf: Workflow, job_id: str) -> Workflow:
        return Workflow(wf.name, _top_env_9770(wf.lines, entry))
    return edit


class PairMirrorFixtures9770(unittest.TestCase):
    """#9770: every PAIRS row compares the whole rust-cache step and each mirrored cargo step."""

    def test_the_real_workflows_have_no_pair_mirror_problem(self) -> None:
        for pair in PAIRS:
            with self.subTest(pair=pair[2]):
                self.assertEqual(_pair_problems_9770(pair), [])

    def test_issue_mutant_step_env_on_the_pr_rust_cache_step(self) -> None:
        for pair in PAIRS:
            with self.subTest(pair=pair[2]):
                problems = _cache_edit_9770("pr", pair,
                                            _add_step_key_9770("env", [FIXTURE_ENV_BLOCK]))
                self.assertEqual(problems, [_differs_9770(
                    pair, RUST_CACHE, RUST_CACHE, "env", FIXTURE_ENV_BLOCK, None)])

    def test_issue_mutant_step_env_on_a_warm_cargo_step(self) -> None:
        for pair in PAIRS:
            _, warm_cargo = PAIR_STEP_NAMES_9770[pair[0]][:2]
            with self.subTest(pair=pair[2]):
                problems = _mutated_9770(pair, "warm", lambda wf, job: _on_step_9770(
                    wf, job, warm_cargo, _add_step_key_9770("env", [FIXTURE_ENV_BLOCK])))
                self.assertEqual(problems, [_table_9770(
                    pair, "warm", warm_cargo, "env", FIXTURE_ENV_BLOCK, None)])

    def test_a_step_env_on_the_pr_cargo_step_is_pinned_too(self) -> None:
        for pair in PAIRS:
            pr_cargo = PAIR_STEP_NAMES_9770[pair[0]][0]
            with self.subTest(pair=pair[2]):
                if pair[0] == "coverage.yml":
                    problems = _mutated_9770(pair, "pr", lambda wf, job: _on_step_9770(
                        wf, job, pr_cargo, _add_step_key_9770("env", [FIXTURE_ENV_BLOCK])))
                    self.assertEqual(problems, [_table_9770(
                        pair, "pr", pr_cargo, "env", FIXTURE_ENV_BLOCK, None)])
                else:
                    problems = _mutated_9770(pair, "pr", lambda wf, job: _on_step_9770(
                        wf, job, pr_cargo, _sub_in_lines_9770("CI_NODE: ${{ matrix.node }}",
                                                              "CI_NODE: other")))
                    self.assertEqual(problems, [
                        f"{pair[0]}:{pair[1]} step {pr_cargo!r}: key 'env' is "
                        f"{CI_CARGO_ENV_9770.replace(NODE_MARK_9770, 'other')!r}, the hand table "
                        f"says {CI_CARGO_ENV_9770.replace(NODE_MARK_9770, 'ubuntu-latest')!r}"])

    def test_every_added_step_key_on_either_side_of_the_rust_cache_step(self) -> None:
        added = (("env", [FIXTURE_ENV_BLOCK], FIXTURE_ENV_BLOCK), ("run", "echo x", "echo x"),
                 ("shell", "bash", "bash"), ("working-directory", "x", "x"),
                 ("continue-on-error", "true", "true"), ("timeout-minutes", "5", "5"))
        for pair in PAIRS:
            for side in SIDES_9770:
                for key, value, seen in added:
                    with self.subTest(pair=pair[2], side=side, key=key):
                        problems = _cache_edit_9770(side, pair, _add_step_key_9770(key, value))
                        pr_value, warm_value = (seen, None) if side == "pr" else (None, seen)
                        self.assertEqual(problems, [_differs_9770(
                            pair, RUST_CACHE, RUST_CACHE, key, pr_value, warm_value)])

    def test_every_unpinned_step_key_added_to_either_cargo_step(self) -> None:
        added = (*[(key, "x", "x") for key in UNPINNED_ABSENT_STEP_KEYS],
                 ("uses", "owner/action@v1", "owner/action@v1"),
                 ("with", ["a: b"], "a: b"), ("id", "x", "x"))
        for pair in PAIRS:
            pr_cargo, warm_cargo = PAIR_STEP_NAMES_9770[pair[0]][:2]
            for side in SIDES_9770:
                ident = pr_cargo if side == "pr" else warm_cargo
                for key, value, seen in added:
                    if key == "id" and pair[0] == "coverage.yml":
                        continue  # pinned by the hand table (id: sweep, #9263); see the test below
                    with self.subTest(pair=pair[2], side=side, key=key):
                        problems = _mutated_9770(pair, side, lambda wf, job: _on_step_9770(
                            wf, job, ident, _add_step_key_9770(key, value)))
                        pr_value, warm_value = (seen, None) if side == "pr" else (None, seen)
                        self.assertEqual(problems, [_differs_9770(
                            pair, pr_cargo, warm_cargo, key, pr_value, warm_value)])

    def test_the_coverage_sweep_id_is_pinned_on_the_pr_cargo_step_9263(self) -> None:
        """#9263 gave `Generate coverage JSON` the id `sweep` that its end-of-sweep step reads."""
        pair = PAIRS[1]
        pr_cargo, warm_cargo = PAIR_STEP_NAMES_9770[pair[0]][:2]
        renamed = _mutated_9770(pair, "pr", lambda wf, job: _on_step_9770(
            wf, job, pr_cargo, _sub_in_lines_9770("id: sweep", "id: zz")))
        self.assertEqual(renamed, [_table_9770(pair, "pr", pr_cargo, "id", "zz", "sweep")])
        warm_added = _mutated_9770(pair, "warm", lambda wf, job: _on_step_9770(
            wf, job, warm_cargo, _add_step_key_9770("id", "sweep")))
        self.assertEqual(warm_added, [_table_9770(pair, "warm", warm_cargo, "id", "sweep", None)])

    def test_a_changed_uses_or_with_on_a_mirrored_step_on_either_side(self) -> None:
        for pair in PAIRS:
            real_pr = {s.label() if s.uses_name() != RUST_CACHE else RUST_CACHE: s
                       for s in Workflow.load(pair[0]).jobs()[pair[1]].steps()}
            real_with = _relative(real_pr[RUST_CACHE].blocks["with"], KEY_INDENT + 2)
            real_uses = real_pr["actions/checkout"].keys["uses"]
            for side in SIDES_9770:
                with self.subTest(pair=pair[2], side=side, key="uses"):
                    problems = _mutated_9770(pair, side, lambda wf, job: _on_step_9770(
                        wf, job, "actions/checkout", _sub_in_lines_9770("@", "@v0-")))
                    mutated = real_uses.replace("@", "@v0-", 1)
                    pr_value, warm_value = ((mutated, real_uses) if side == "pr"
                                            else (real_uses, mutated))
                    self.assertEqual(problems, [_differs_9770(
                        pair, "actions/checkout", "actions/checkout", "uses", pr_value, warm_value)])
                with self.subTest(pair=pair[2], side=side, key="with"):
                    shared = pair[3]
                    problems = _cache_edit_9770(side, pair, _sub_in_lines_9770(
                        f"shared-key: {shared}", f"shared-key: {shared}-x"))
                    mutated = real_with.replace(f"shared-key: {shared}",
                                                f"shared-key: {shared}-x", 1)
                    pr_value, warm_value = ((mutated, real_with) if side == "pr"
                                            else (real_with, mutated))
                    self.assertEqual(problems, [_differs_9770(
                        pair, RUST_CACHE, RUST_CACHE, "with", pr_value, warm_value)])

    def test_a_changed_run_on_a_mirrored_step_on_either_side(self) -> None:
        for pair in PAIRS:
            run_step = PAIR_STEP_NAMES_9770[pair[0]][2]  # a mirrored step with a block run
            real = {s.label(): s for s in Workflow.load(pair[0]).jobs()[pair[1]].steps()}[run_step]
            for side in SIDES_9770:
                with self.subTest(pair=pair[2], side=side):
                    problems = _mutated_9770(pair, side, lambda wf, job: _on_step_9770(
                        wf, job, run_step, _append_run_line_9770))
                    mutated = real.run() + "\necho mutated-9770"
                    pr_value, warm_value = ((mutated, real.run()) if side == "pr"
                                            else (real.run(), mutated))
                    self.assertEqual(problems, [_differs_9770(
                        pair, run_step, run_step, "run", pr_value, warm_value)])

    def test_an_unknown_step_key_on_either_side_names_workflow_job_step_and_key(self) -> None:
        for pair in PAIRS:
            for side in SIDES_9770:
                wf_name, job_id = _side_ids_9770(pair, side)
                with self.subTest(pair=pair[2], side=side):
                    problems = _cache_edit_9770(side, pair, _add_step_key_9770("bogus-key", "1"))
                    self.assertEqual(problems, [f"{wf_name}:{job_id} step {RUST_CACHE!r}: step key "
                                                "'bogus-key' is not a known step key"])

    def test_an_unmapped_missing_or_duplicated_step_is_a_problem(self) -> None:
        for pair in PAIRS:
            disk = PAIR_STEP_NAMES_9770[pair[0]][2]
            for side in SIDES_9770:
                wf_name, job_id = _side_ids_9770(pair, side)
                with self.subTest(pair=pair[2], side=side, case="unmapped"):
                    problems = _mutated_9770(pair, side, lambda wf, job: _add_step_9770(job, wf))
                    self.assertEqual(problems, [f"{wf_name}:{job_id} step {FIXTURE_EXTRA_STEP!r}: "
                                                "no row in the mirror table"])
                with self.subTest(pair=pair[2], side=side, case="missing"):
                    problems = _mutated_9770(pair, side, lambda wf, job: _drop_step_9770(
                        wf, job, disk))
                    self.assertEqual(problems, [f"{wf_name}:{job_id}: no step {disk!r} "
                                                "(the mirror table needs it)"])
                with self.subTest(pair=pair[2], side=side, case="duplicate"):
                    problems = _mutated_9770(pair, side, lambda wf, job: _duplicate_step_9770(
                        wf, job, disk))
                    self.assertEqual(problems, [f"{wf_name}:{job_id}: step {disk!r} "
                                                "appears 2 times"])
                with self.subTest(pair=pair[2], side=side, case="triplicate"):
                    problems = _mutated_9770(pair, side, lambda wf, job: _triplicate_step_9770(
                        wf, job, disk))
                    self.assertEqual(problems, [f"{wf_name}:{job_id}: step {disk!r} "
                                                "appears 3 times"])

    def test_the_hand_table_pins_the_allowed_differences(self) -> None:
        ci_if_hosted = ("needs.classify.outputs.cargo_skip != 'true' && runner.environment == "
                        "'github-hosted' && env.LEG_SKIP != 'true'")
        ci_if_runs = "needs.classify.outputs.cargo_skip != 'true' && env.LEG_SKIP != 'true'"
        ci = PAIR_TABLES[("ci.yml", "check")]
        self.assertEqual(ci.row_for(RUST_CACHE).allowed["if"], (ci_if_hosted, None))
        self.assertEqual(ci.row_for(RUST_CACHE).allowed["id"], (None, "rust-cache"))
        self.assertEqual(ci.row_for("Install Rust 1.99.1 (matches rust-toolchain.toml pin)")
                         .allowed["if"], (ci_if_runs, None))
        self.assertEqual(ci.row_for("Run tests (impact-aware)").allowed["shell"], ("bash", None))
        self.assertEqual(ci.row_for("Run tests (impact-aware)").allowed["if"],
                         (ci_if_runs, "steps.rust-cache.outputs.cache-hit != 'true'"))
        self.assertEqual(ci.row_for("Run tests (impact-aware)").allowed["env"][1], None)
        self.assertEqual(ci.job_allowed["needs"], ("classify", None))
        self.assertEqual(ci.job_allowed["runs-on"], ('["ubuntu-latest"]', "ubuntu-latest"))
        self.assertEqual(ci.row_for("Low-mem hosted sqlite link (debuginfo=0, system ld "
                                    "— mold isolation)").allowed["if"],
                         ("needs.classify.outputs.cargo_skip != 'true' && matrix.leg == "
                          "'ubuntu-latest,sqlite' && env.LEG_SKIP != 'true'", None))
        self.assertIn("Draft skip (#9821)", ci.pr_only)
        self.assertEqual(ci.env_one_sided,
                         {"SELF_HOSTED_TARGET_CAP_BYTES": "pr", "LEG_SKIP": "pr"})
        cov = PAIR_TABLES[("coverage.yml", "per-module-thresholds")]
        self.assertEqual(cov.row_for("Install cargo-llvm-cov").allowed["if"],
                         (None, "steps.rust-cache.outputs.cache-hit != 'true'"))
        self.assertEqual(cov.row_for("Generate coverage JSON").allowed["env"], (None, None))
        self.assertEqual(cov.job_allowed["if"], ("needs.classify.outputs.cargo_skip != 'true'", None))
        self.assertEqual(cov.row_for("Generate coverage JSON").allowed["id"], ("sweep", None))
        self.assertEqual(cov.job_allowed["permissions"],
                         ("contents: read\npull-requests: write", None))
        self.assertEqual(cov.env_one_sided, {})
        for table in PAIR_TABLES.values():
            self.assertNotIn("steps", table.job_allowed)
            self.assertNotIn("env", table.job_allowed)

    def test_every_added_job_key_on_either_side(self) -> None:
        for pair in PAIRS:
            for side in SIDES_9770:
                wf_name, job_id = _side_ids_9770(pair, side)
                for key in UNPINNED_ABSENT_JOB_KEYS:
                    with self.subTest(pair=pair[2], side=side, key=key):
                        problems = _mutated_9770(pair, side, lambda wf, job: _on_job_9770(
                            wf, job, _add_job_key_9770(key, "x")))
                        pr_value, warm_value = ("x", None) if side == "pr" else (None, "x")
                        self.assertEqual(problems, [
                            f"{pair[0]}:{pair[1]} vs {WARM}:{pair[2]}: job key {key!r} differs: "
                            f"{pair[0]} has {pr_value!r}, {WARM} has {warm_value!r}"])
                with self.subTest(pair=pair[2], side=side, key="defaults"):
                    problems = _mutated_9770(pair, side, lambda wf, job: _on_job_9770(
                        wf, job, _add_job_key_9770("defaults", ["run:", "  shell: bash"])))
                    seen = "run:\n  shell: bash"
                    pr_value, warm_value = (seen, None) if side == "pr" else (None, seen)
                    self.assertEqual(problems, [
                        f"{pair[0]}:{pair[1]} vs {WARM}:{pair[2]}: job key 'defaults' differs: "
                        f"{pair[0]} has {pr_value!r}, {WARM} has {warm_value!r}"])
                with self.subTest(pair=pair[2], side=side, key="container"):
                    problems = _mutated_9770(pair, side, lambda wf, job: _on_job_9770(
                        wf, job, _add_job_key_9770("container", "ubuntu:24.04")))
                    pr_value, warm_value = (("ubuntu:24.04", None) if side == "pr"
                                            else (None, "ubuntu:24.04"))
                    self.assertEqual(problems, [
                        f"{pair[0]}:{pair[1]} vs {WARM}:{pair[2]}: job key 'container' differs: "
                        f"{pair[0]} has {pr_value!r}, {WARM} has {warm_value!r}"])
                with self.subTest(pair=pair[2], side=side, key="bogus"):
                    problems = _mutated_9770(pair, side, lambda wf, job: _on_job_9770(
                        wf, job, _add_job_key_9770("bogus-job-key", "1")))
                    self.assertEqual(problems, [f"{wf_name}:{job_id}: job key 'bogus-job-key' is "
                                                "not a known job key"])

    def test_a_changed_runs_on_on_either_side(self) -> None:
        expected = {
            ("ci.yml", "pr"): "job key 'runs-on' is 'ubuntu-22.04', the hand table says "
                              "'[\"ubuntu-latest\"]'",
            ("ci.yml", "warm"): "job key 'runs-on' is 'ubuntu-22.04', the hand table says "
                                "'ubuntu-latest'",
        }
        for pair in PAIRS:
            for side in SIDES_9770:
                wf_name, job_id = _side_ids_9770(pair, side)
                with self.subTest(pair=pair[2], side=side):
                    problems = _mutated_9770(pair, side, lambda wf, job: _on_job_9770(
                        wf, job, _set_job_line_9770("runs-on", "ubuntu-22.04")))
                    if (pair[0], side) in expected:
                        self.assertEqual(problems, [f"{wf_name}:{job_id}: " + expected[(pair[0], side)]])
                    else:
                        pr_value, warm_value = (("ubuntu-22.04", "ubuntu-latest") if side == "pr"
                                                else ("ubuntu-latest", "ubuntu-22.04"))
                        self.assertEqual(problems, [
                            f"{pair[0]}:{pair[1]} vs {WARM}:{pair[2]}: job key 'runs-on' differs: "
                            f"{pair[0]} has {pr_value!r}, {WARM} has {warm_value!r}"])

    def test_the_pinned_job_keys_refuse_a_change_on_either_side(self) -> None:
        for side in SIDES_9770:
            wf_name, job_id = _side_ids_9770(PAIRS[0], side)
            with self.subTest(pair="ci", side=side, key="needs"):
                problems = _mutated_9770(PAIRS[0], side, lambda wf, job: _on_job_9770(
                    wf, job, _set_job_line_9770("needs", "other") if side == "pr"
                    else _add_job_key_9770("needs", "classify")))
                actual, expected = ("other", "classify") if side == "pr" else ("classify", None)
                self.assertEqual(problems, [f"{wf_name}:{job_id}: job key 'needs' is {actual!r}, "
                                            f"the hand table says {expected!r}"])
        for side in SIDES_9770:
            wf_name, job_id = _side_ids_9770(PAIRS[1], side)
            with self.subTest(pair="coverage", side=side, key="if"):
                problems = _mutated_9770(PAIRS[1], side, lambda wf, job: _on_job_9770(
                    wf, job, _set_job_line_9770("if", "true") if side == "pr"
                    else _add_job_key_9770("if", "true")))
                expected = "needs.classify.outputs.cargo_skip != 'true'" if side == "pr" else None
                self.assertEqual(problems, [f"{wf_name}:{job_id}: job key 'if' is 'true', "
                                            f"the hand table says {expected!r}"])
            with self.subTest(pair="coverage", side=side, key="permissions"):
                problems = _mutated_9770(PAIRS[1], side, lambda wf, job: _on_job_9770(
                    wf, job, _add_job_key_9770("permissions", "write-all") if side == "warm"
                    else _set_perm_9770))
                actual = "write-all"
                expected = None if side == "warm" else "contents: read\npull-requests: write"
                self.assertEqual(problems, [f"{wf_name}:{job_id}: job key 'permissions' is "
                                            f"{actual!r}, the hand table says {expected!r}"])

    def test_a_workflow_or_job_env_var_on_either_side(self) -> None:
        for pair in PAIRS:
            for side in SIDES_9770:
                for level in ("workflow", "job"):
                    with self.subTest(pair=pair[2], side=side, level=level):
                        if level == "workflow":
                            def edit(wf: Workflow, job: str) -> Workflow:
                                return Workflow(wf.name, _top_env_9770(wf.lines))
                        else:
                            def edit(wf: Workflow, job: str) -> Workflow:
                                return _on_job_9770(wf, job, _add_env_9770(4))
                        problems = _mutated_9770(pair, side, edit)
                        pr_value, warm_value = ((FIXTURE_ENV_VALUE, None) if side == "pr"
                                                else (None, FIXTURE_ENV_VALUE))
                        self.assertEqual(problems, [
                            f"{pair[0]}:{pair[1]} vs {WARM}:{pair[2]}: env {FIXTURE_ENV_NAME!r} "
                            f"differs: {pair[0]} has {pr_value!r}, {WARM} has {warm_value!r}"])

    def test_the_one_sided_env_is_allowed_on_the_pr_side_only(self) -> None:
        pair = PAIRS[0]
        name = "SELF_HOSTED_TARGET_CAP_BYTES"
        problems = _mutated_9770(pair, "warm", lambda wf, job: Workflow(
            wf.name, _top_env_9770(wf.lines, f"{name}: 1")))
        self.assertEqual(problems, [
            f"{pair[0]}:{pair[1]} vs {WARM}:{pair[2]}: env {name!r} differs: "
            f"{pair[0]} has None, {WARM} has '1'"])

    def test_an_unevaluable_env_value_is_a_problem_naming_the_variable(self) -> None:
        pair = PAIRS[0]
        problems = _mutated_9770(pair, "pr", _env_edit_9770(UNEVALUABLE_ENV_9770))
        self.assertEqual(problems, [f"{SIDE_LABELS_9770[pair[0]][0]}: {UNEVALUABLE_ENV_TAIL_9770}"])

    def test_the_env_check_reports_every_side_that_failed_and_invents_no_value(self) -> None:
        bad = _env_edit_9770(UNEVALUABLE_ENV_9770)
        plain = _env_edit_9770("FOO: a")
        for pair in PAIRS:
            pr_label, warm_label = SIDE_LABELS_9770[pair[0]]
            pr_line = f"{pr_label}: {UNEVALUABLE_ENV_TAIL_9770}"
            warm_line = f"{warm_label}: {UNEVALUABLE_ENV_TAIL_9770}"
            # (case, PR edit, warm edit, exact problems)
            cases = (
                ("both fail", bad, bad, [pr_line, warm_line]),
                ("only the PR side fails, the warm side lacks the variable", bad, _keep_9770,
                 [pr_line]),
                ("only the warm side fails, the PR side lacks the variable", _keep_9770, bad,
                 [warm_line]),
                ("the PR side fails, the warm side reads a value", bad, plain, [pr_line]),
                ("the warm side fails, the PR side reads a value", plain, bad, [warm_line]),
            )
            for case, pr_edit, warm_edit, expected in cases:
                with self.subTest(pair=pair[2], case=case):
                    self.assertEqual(_both_sides_9770(pair, pr_edit, warm_edit), expected)

    def test_a_runs_on_that_cannot_be_read_names_the_side_that_failed(self) -> None:
        for pair in PAIRS:
            pr_label, warm_label = SIDE_LABELS_9770[pair[0]]
            pr_line = f"{pr_label}: runs-on cannot be read: {RUNS_ON_TAIL_9770[(pair[0], 'pr')]}"
            warm_line = (f"{warm_label}: runs-on cannot be read: "
                         f"{RUNS_ON_TAIL_9770[(pair[0], 'warm')]}")
            # (case, PR edit, warm edit, exact problems); a side that failed is never compared.
            cases = (
                ("PR side", _runs_on_unread_9770, _keep_9770, [pr_line]),
                ("warm side", _keep_9770, _runs_on_unread_9770, [warm_line]),
                ("both sides", _runs_on_unread_9770, _runs_on_unread_9770, [pr_line, warm_line]),
            )
            for case, pr_edit, warm_edit, expected in cases:
                with self.subTest(pair=pair[2], case=case):
                    self.assertEqual(_both_sides_9770(pair, pr_edit, warm_edit), expected)

    def test_a_workflow_level_defaults_on_either_side(self) -> None:
        for pair in PAIRS:
            for side in SIDES_9770:
                with self.subTest(pair=pair[2], side=side):
                    problems = _mutated_9770(pair, side, lambda wf, job: Workflow(
                        wf.name, _top_defaults_9770(wf.lines)))
                    seen = "run:\n  shell: bash"
                    pr_value, warm_value = (seen, None) if side == "pr" else (None, seen)
                    self.assertEqual(problems, [
                        f"{pair[0]} vs {WARM}: workflow key 'defaults' differs: "
                        f"{pair[0]} has {pr_value!r}, {WARM} has {warm_value!r}"])


def _top_env_9770(lines: list[str], entry: str = FIXTURE_ENV_BLOCK) -> list[str]:
    hits = [i for i, line in enumerate(lines) if line.rstrip() == "env:"]
    if len(hits) != 1:
        raise AssertionError(f"fixture: top-level env found {len(hits)} times")
    return [*lines[:hits[0] + 1], f"  {entry}", *lines[hits[0] + 1:]]


def _top_defaults_9770(lines: list[str]) -> list[str]:
    hits = [i for i, line in enumerate(lines) if line.startswith("jobs:")]
    if len(hits) != 1:
        raise AssertionError("fixture: jobs: found more than once")
    return [*lines[:hits[0]], "defaults:", "  run:", "    shell: bash", *lines[hits[0]:]]


def _set_perm_9770(seg: list[str]) -> list[str]:
    hits = [i for i, line in enumerate(seg)
            if _indent(line) == 4 and line.strip().startswith("permissions:")]
    if len(hits) != 1:
        raise AssertionError("fixture: permissions found other than once")
    stop = next((i for i in range(hits[0] + 1, len(seg))
                 if seg[i].strip() and _indent(seg[i]) <= 4), len(seg))
    return [*seg[:hits[0]], "    permissions: write-all", *seg[stop:]]


if __name__ == "__main__":
    unittest.main()
