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
generation constant at the four paired cache steps invalidates it. ``ChainCacheSoleWriter9681``
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
SHARED_KEYS = tuple(pair[3] for pair in PAIRS)
KEY_HOLDERS = frozenset({"ci.yml", "coverage.yml", WARM})
# Workflows started by these events run with a base-branch token and may write the base cache.
PRIVILEGED_EVENTS = frozenset({"pull_request_target", "workflow_run"})
CACHE_USES_RE = re.compile(r"""^\s*(?:-\s+)?uses:\s*['"]?(Swatinem/rust-cache|actions/cache)(?:[/@]|['"]?\s*$)""")
USES_RE = re.compile(r"""^\s*(?:-\s+)?uses:\s*['"]?([^'"\s#]+)""")
PINNED_USES_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$")
WARM_FORBIDDEN_RE = re.compile(r"upload-artifact|id-token|\bsecrets\s*[.:\[]")
# V-7: one generation constant at the four paired cache steps; a bump changes every chain key.
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
        out: dict[str, str] = {}
        for line in self.blocks.get(key, []):
            if _is_comment_or_blank(line) or _indent(line) != KEY_INDENT + 2:
                continue
            name, _, value = line.strip().partition(":")
            out[name] = _scalar(value)
        return out

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


def _mapping(lines: list[str], indent: int) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in lines:
        if _is_comment_or_blank(line) or _indent(line) != indent:
            continue
        name, _, value = line.strip().partition(":")
        out[name] = _scalar(value)
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


def _effective_env_value(name: str, raw: str, leg: dict[str, object]) -> str:
    """The value env var `name` takes on one leg; an expression form other than one fails."""
    if EXPRESSION_OPEN not in raw:
        return raw
    match = MATRIX_OR_LITERAL_RE.match(raw)
    if not match:
        raise AssertionError(f"{name}: unrecognised expression form in an env value: {raw!r}")
    field_name, literal = match.groups()
    value = leg.get(field_name)
    if value is None or value == "":
        return literal
    # `||` takes the literal for a falsy matrix value (false, 0, ''). _scalar drops quoting, so a
    # quoted '0' (a truthy string) and a bare 0 (falsy) read the same: refuse rather than guess.
    if isinstance(value, bool) or str(value).strip() in ("0", "0.0", "-0"):
        raise AssertionError(f"{name}: matrix.{field_name} = {value!r} is truthy when quoted and "
                             f"falsy when not, and this parser drops the quotes: {raw!r}")
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


class RustCacheSaveScope9681(unittest.TestCase):
    """Every cache write in a PR-startable workflow comes from a push run (#9681)."""

    def test_rust_cache_sites_match_the_hand_table(self) -> None:
        found: dict[str, dict[str, int]] = {}
        for name in _all_workflow_names():
            wf = Workflow.load(name)
            if not PR_EVENTS & set(wf.events()):
                continue
            for job_id, job in wf.jobs().items():
                count = sum(1 for s in job.steps() if s.uses_name() == RUST_CACHE)
                if count:
                    found.setdefault(name, {})[job_id] = count
        self.assertEqual(found, RUST_CACHE_SITES)

    def test_every_rust_cache_step_saves_only_on_push(self) -> None:
        for name in [*RUST_CACHE_SITES, WARM]:
            wf = Workflow.load(name)
            for job_id, job in wf.jobs().items():
                for step in job.steps():
                    if step.uses_name() != RUST_CACHE:
                        continue
                    with self.subTest(workflow=name, job=job_id):
                        self.assertEqual(step.keys["uses"].split("@", 1)[1], RUST_CACHE_SHA)
                        self.assertEqual(step.mapping("with").get("save-if"), SAVE_IF_PUSH)
                        self.assertNotIn("cache-on-failure", step.mapping("with"))

    def test_no_pr_run_saves_an_actions_cache(self) -> None:
        for name in _all_workflow_names():
            wf = Workflow.load(name)
            if not PR_EVENTS & set(wf.events()):
                continue
            for job_id, job in wf.jobs().items():
                for step in job.steps():
                    with self.subTest(workflow=name, job=job_id, step=step.label()):
                        self.assertNotEqual(step.uses_name(), CACHE_COMBINED,
                                            "actions/cache saves in its post step on every event")
                        if step.uses_name() == CACHE_SAVE:
                            self.assertTrue(step.keys.get("if", "").startswith(PUSH_GATE),
                                            step.keys.get("if"))

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
        shared_keys: dict[str, list[str]] = {}
        for name in [*RUST_CACHE_SITES, WARM]:
            for job_id, job in Workflow.load(name).jobs().items():
                for step in job.steps():
                    if step.uses_name() == RUST_CACHE and "shared-key" in step.mapping("with"):
                        shared_keys.setdefault(step.mapping("with")["shared-key"], []).append(
                            f"{name}:{job_id}")
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
                                         f"cache key {literal!r} is used outside the four paired "
                                         f"rust-cache steps (V-4)")
        for name in _all_workflow_names():
            for job_id, job in Workflow.load(name).jobs().items():
                for step in job.steps():
                    if step.uses_name() != RUST_CACHE:
                        continue
                    inputs = step.mapping("with")
                    owner = any((name, job_id) in ((p[0], p[1]), (WARM, p[2])) for p in PAIRS)
                    with self.subTest(workflow=name, job=job_id):
                        for key in ("shared-key", "prefix-key"):
                            value = inputs.get(key, "")
                            where = f"{name}:{_job_line(name, job_id, f'{key}:')} (job {job_id})"
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

    def test_v7_one_prefix_key_generation_at_the_four_paired_steps(self) -> None:
        sites = {}
        for pr_name, pr_job_id, warm_job_id, _ in PAIRS:
            for name, job_id in ((pr_name, pr_job_id), (WARM, warm_job_id)):
                _, inputs = _cache_step_inputs(name, job_id)
                sites[f"{name}:{job_id}"] = inputs.get("prefix-key")
        self.assertEqual(len(sites), 4)
        values = set(sites.values())
        self.assertEqual(len(values), 1, f"prefix-key differs across the four paired cache steps: "
                                         f"{sites} (V-7)")
        (value,) = values
        self.assertIsNotNone(value, f"no prefix-key at the four paired cache steps: {sites} (V-7)")
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


def _matrix_include(job: Job) -> list[dict[str, object]]:
    """The `strategy.matrix.include` entries of a job, scalar values only."""
    entries: list[dict[str, object]] = []
    include_indent = -1
    item_indent = -1
    for line in job.block("strategy"):
        if _is_comment_or_blank(line):
            continue
        stripped = line.strip()
        if stripped == "include:":
            include_indent = _indent(line)
            continue
        if include_indent < 0:
            continue
        if _indent(line) <= include_indent:
            break
        if stripped.startswith("- ") and (item_indent < 0 or _indent(line) == item_indent):
            item_indent = _indent(line)
            entries.append({})
            stripped = stripped[2:]
        elif _indent(line) != item_indent + 2:
            continue
        name, _, value = stripped.partition(":")
        scalar = _scalar(value)
        entries[-1][name.strip()] = {"true": True, "false": False}.get(scalar, scalar)
    return entries


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
    "./.github/actions/docs-only-gate": "local composite action (#9683); it uses no action and no cache "
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


def _pr_cache_writers() -> tuple[list[tuple[str, str, str]], list[str]]:
    """(writers a PR run reaches, problems) across every PR-startable workflow and the warm one."""
    reached: list[tuple[str, str, str]] = []
    problems: list[str] = []
    for name in _all_workflow_names():
        wf = Workflow.load(name)
        pr_run = bool(PR_EVENTS & set(wf.events()))
        if not pr_run and name != WARM:
            continue
        for job_id, job in wf.jobs().items():
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
# because the leg is off the long pole and #9732 owns its warm cache.
V12_COLD = ("vote V-12 accepted cost (#9681): no warm job, saves on push only; whether warm "
            "entries survive eviction is #9721")
V12_ISSUES = (9681, 9721)
UNPAIRED_RUST_CACHE_SITES: dict[tuple[str, str, str], UnpairedSite] = {
    ("ci.yml", "lint", ""): UnpairedSite(V12_ISSUES, V12_COLD),
    ("ci.yml", "postgres-feature", ""): UnpairedSite(V12_ISSUES, V12_COLD),
    ("ci.yml", "mobile-cross-compile", "target=aarch64-apple-ios"): UnpairedSite(V12_ISSUES, V12_COLD),
    ("ci.yml", "mobile-cross-compile", "target=aarch64-linux-android"): UnpairedSite(
        (9721, 9732),
        "the `once` leg runs the cargo-audit install and the release smoke that #9680 moved off "
        "`check`, under its own key `mobile-<target>-audit-release`; no chain push warms it (#9732)",
        ("cargo build --release",
         "cargo check --target aarch64-linux-android --no-default-features --features "
         "sqlite-bundled --lib",
         "cargo install cargo-audit --locked --force --version 0.22.2")),
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
    if not match:
        raise AssertionError(f"{job.job_id}: unrecognised runs-on form: {raw!r}")
    field_name = match.group(1) or match.group(2)
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
        for job_id, job in wf.jobs().items():
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
                    sites[(name, job_id, _leg_id(leg))] = (wf, job, leg)
    return sites, problems


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

        self.assertEqual(_unpaired_site_problems(frozenset(sites), paired,
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
        cases = {
            "ubuntu-latest": "ubuntu-latest",
            "[self-hosted, linux-fed]": "[self-hosted, linux-fed]",
            "${{ matrix.os }}": "ubuntu-latest",
            "${{ fromJSON(matrix.runner) }}": '["self-hosted","linux-fed"]',
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(_runs_on(job(raw), leg), expected)
        failures = {
            "${{ inputs.runner }}": "j: unrecognised runs-on form: '${{ inputs.runner }}'",
            "${{ matrix.missing }}": "j: runs-on reads matrix.missing, which leg "
                                     "'os=ubuntu-latest' does not set",
        }
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
            lines = [f"    runs-on: {runs_on}", "    strategy:", "      matrix:", "        include:"]
            for leg in legs:
                lines.append(f"          - {leg}")
            return Job("j", lines)

        by_os = job("${{ matrix.os }}", "os: ubuntu-latest", "os: '[self-hosted, linux-fed]'")
        self.assertEqual(_hosted_legs(by_os), [{"os": "ubuntu-latest"}])
        self.assertEqual(_hosted_legs(job("[self-hosted, linux-fed]")), [])
        self.assertEqual(_hosted_legs(job("ubuntu-latest")), [{}])
        with self.assertRaises(AssertionError) as caught:
            _hosted_legs(job("${{ inputs.runner }}", "runner: ubuntu-latest"))
        self.assertEqual(str(caught.exception),
                         "j: unrecognised runs-on form: '${{ inputs.runner }}'")


if __name__ == "__main__":
    unittest.main()
