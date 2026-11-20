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

Run: python3 -I -m unittest discover -s scripts/ci/tests -p 'test_rust_cache_save_scope_9681.py'
"""

from __future__ import annotations

import re
import sys
import unittest
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
        "classify": ("run: # TWO SEPARATE BASES (#2496). Sharing one was the defect.",
                     "run: emit_all() {",
                     "Test impact selector security fallbacks",
                     "Workflow concurrency invariants (#6340)",
                     "Fetch the corpus replay objects (#7988)",
                     "Fetch the amendment ledger replay objects (#9303)",
                     "Shard partition and wiring unit tests (#6344)",
                     "AGE self-heal helper unit test (#6161)",
                     "Target sweep unit tests (#7160)"),
        "lint": ("Check formatting", "Clippy",
                 "Clippy (all targets, sal — cfg-stripped doc-lint class)"),
        "build-script-vetting": ("Verify every custom-build package is ledgered",
                                 "Self-test (prove the gate is load-bearing)"),
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
                  "Security audit",
                  "Build release (once leg — release-profile smoke)",
                  "Cleanup enterprise-fed ephemeral db",
                  "sccache hit-rate summary (#7199)",
                  "sccache stop CI server (#7199)",
                  "Prune stale runner artifacts (#7188)",
                  "Sweep target/debug to the size cap (self-hosted)",
                  "Sweep per-runner cargo target to the size cap (self-hosted,"),
        "postgres-feature": ("Clippy (sal-postgres feature, lib + tests)",),
        "mobile-cross-compile": ("cargo check (--lib --features sqlite-bundled)",),
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
# Compile commands: each must appear in the PR job's run text and in the warm job's run text.
WARM_COMPILES: dict[tuple[str, str], tuple[str, ...]] = {
    # Not `cargo install cargo-audit`: the PR job installs it with --force into a throwaway
    # target, so a warm install would cost hosted minutes and restore nothing the PR uses.
    ("ci.yml", "check"): ("cargo test --no-run", "cargo build --release"),
    ("coverage.yml", "per-module-thresholds"): (
        "cargo llvm-cov --no-report --features sal,sal-postgres --lib --tests --workspace",),
}

# HuggingFace model cache of coverage.yml: restore on every event, save on push only.
HF_CACHE_SITES = {
    ("coverage.yml", "per-module-thresholds"): ("Restore HuggingFace models (#2019)",
                                                "Save HuggingFace models (#2019, push only)"),
    (WARM, "coverage"): ("Restore HuggingFace models (#2019)",
                         "Save HuggingFace models (#2019, push only)"),
}


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


def _key_env(env: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in env.items() if k.startswith(KEY_ENV_PREFIXES) and v != ""}


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
                    for absent in ("key", "prefix-key", "add-job-id-key",
                                   "add-rust-environment-hash-key", "env-vars", "workspaces"):
                        self.assertNotIn(absent, inputs)
                self.assertEqual(sorted(shared_keys[shared_key]),
                                 sorted([f"{pr_name}:{pr_job_id}", f"{WARM}:{warm_job_id}"]))
            with self.subTest(pair=warm_job_id, part="key-env"):
                pr_env = {**pr_wf.env(), **pr_job.env()}
                warm_env = {**warm.env(), **warm_job.env()}
                self.assertEqual(_key_env(warm_env), _key_env(pr_env))
                self.assertEqual({k: v for k, v in warm_env.items()
                                  if not k.startswith(KEY_ENV_PREFIXES)},
                                 {k: v for k, v in warm_env.items()
                                  if k in pr_env and not k.startswith(KEY_ENV_PREFIXES)})
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
            with self.subTest(pair=warm_job_id, part="compiles"):
                pr_text = _flat("\n".join(s.run() for s in pr_steps))
                warm_text = _flat("\n".join(s.run() for s in warm_steps[warm_cache + 1:]))
                for command in WARM_COMPILES[(pr_name, pr_job_id)]:
                    self.assertIn(command, pr_text)
                    self.assertIn(command, warm_text)
            with self.subTest(pair=warm_job_id, part="skip-on-full-match"):
                cache_id = warm_steps[warm_cache].keys["id"]
                gate = f"steps.{cache_id}.outputs.cache-hit != 'true'"
                for step in warm_steps[warm_cache + 1:]:
                    if any(c in _flat(step.run()) for c in WARM_COMPILES[(pr_name, pr_job_id)]):
                        self.assertIn(gate, step.keys.get("if", ""), step.label())

    def test_warm_jobs_run_only_the_hand_table_cargo_commands(self) -> None:
        warm_jobs = Workflow.load(WARM).jobs()
        for pr_name, pr_job_id, warm_job_id, _ in PAIRS:
            compiles = WARM_COMPILES[(pr_name, pr_job_id)]
            for step in warm_jobs[warm_job_id].steps():
                for line in _flat(step.run()).splitlines():
                    if "cargo " not in line or line.lstrip().startswith("#"):
                        continue
                    with self.subTest(job=warm_job_id, line=line.strip()):
                        self.assertTrue(any(c in line for c in compiles), line)

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


if __name__ == "__main__":
    unittest.main()
