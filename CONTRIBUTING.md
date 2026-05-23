# Contributing to ai-memory

Thank you for considering contributing to ai-memory-mcp. This document outlines the process for contributing to this project.

## Reporting Bugs

Open an issue at [GitHub Issues](https://github.com/alphaonedev/ai-memory-mcp/issues) with:

- A clear, descriptive title
- Steps to reproduce the problem
- Expected vs actual behavior
- Your environment (OS, Rust version, build configuration)
- Relevant logs or error output

## Suggesting Features

Open a feature request at [GitHub Issues](https://github.com/alphaonedev/ai-memory-mcp/issues) with:

- A description of the problem the feature would solve
- Your proposed solution
- Any alternatives you have considered

## Development Setup

### Prerequisites

- **Rust 1.87+** (install via [rustup](https://rustup.rs/))
- **C compiler** (gcc, clang, or MSVC)
- Git

### Getting Started

```bash
git clone https://github.com/alphaonedev/ai-memory-mcp.git
cd ai-memory-mcp
git checkout develop
cargo build
AI_MEMORY_NO_CONFIG=1 cargo test
```

## Code Style

- Run `cargo fmt` before committing. All code must be formatted with rustfmt.
- Run `cargo clippy -- -D warnings -D clippy::all -D clippy::pedantic` and resolve all failures. CI will reject code that does not pass this check.
- All new source files must include the copyright header:
  ```rust
  // Copyright 2026 AlphaOne LLC
  // SPDX-License-Identifier: Apache-2.0
  ```
- Follow standard Rust naming conventions and idioms.

## Testing Requirements

All four checks must pass before submitting a PR:

```bash
cargo fmt --check
cargo clippy -- -D warnings -D clippy::all -D clippy::pedantic
AI_MEMORY_NO_CONFIG=1 cargo test
cargo audit
```

- All four checks must pass. CI will reject PRs that fail any of them.
- `AI_MEMORY_NO_CONFIG=1` prevents loading `~/.config/ai-memory/config.toml` which may trigger embedder/LLM initialization.
- New code must include tests. Bug fixes should include a regression test.
- If you add a new MCP tool, HTTP endpoint, or CLI command, include integration tests covering the primary usage path.
- If clippy pedantic requires `#[allow(clippy::...)]`, justify it in your PR description.

## Per-module coverage discipline (v0.7.0 forward)

ai-memory enforces **per-module line coverage thresholds** in CI, on top
of the workspace-wide absolute floor and ratchet that the `Code Coverage`
job in `ci.yml` already enforces. The per-module gate is the
`Per-Module Coverage Thresholds` workflow (`.github/workflows/coverage.yml`).

- Thresholds are defined in [`coverage/thresholds.toml`](coverage/thresholds.toml).
- Thresholds **rise across releases; never fall.** If a module's threshold
  is 87%, your PR cannot lower it; you can raise it. CI rejects any PR
  that drops a module below its current floor.
- Adding new code requires one of:
  1. Hitting the relevant tier threshold for the module's tier, OR
  2. Adding the file to `coverage/thresholds.toml` with a documented
     rationale comment, OR
  3. Adding a structural-ceiling entry in [`coverage/policy.md`](coverage/policy.md)
     with the ship-gate compensation that exercises the unreachable
     surface end-to-end.
- Tier targets (final, raised to these by v0.8.0):
  - **A = 98%** (pure logic — audit, errors, identity, models, validate, etc.)
  - **B = 95%** (API surface — MCP / HTTP / CLI)
  - **C = 92%** (substrate — curator, federation, governance, storage core)
  - **D = 85%** (LLM-bound — auto_tag, detect_contradiction, expand_query, llm)
  - **E = 90%** (wire / IO / infrastructure — daemon_runtime, store, tls, etc.)
- CI runs [`coverage/check-thresholds.sh`](coverage/check-thresholds.sh) on
  every PR. The script parses `coverage/thresholds.toml`, reads the
  `cargo llvm-cov --json` output, and exits non-zero if any module is
  below its threshold.
- **Lowering a threshold requires explicit operator approval in the PR
  description.** Routine PRs that legitimately re-shape a module (e.g.
  a refactor that splits a file) should raise thresholds on the resulting
  modules, not lower the predecessor's.

To run the gate locally before pushing:

```bash
cargo llvm-cov --features sal,sal-postgres --lib --tests --json \
  --output-path coverage/current.json --workspace
bash coverage/check-thresholds.sh
```

## CI infrastructure (v0.7.x — #1148)

The `Code Coverage`, `Per-Module Coverage Thresholds`, and
`Postgres feature gate` jobs run on GitHub-hosted `ubuntu-latest`
(7 GB RAM + 14 GB swap). Without belt-and-suspenders these workloads
hit `collect2: signal 7 [Bus error]` linker-OOM under the
`--features sal,sal-postgres` instrumented build. Issue
[#1148](https://github.com/alphaonedev/ai-memory-mcp/issues/1148)
landed a 12-layer mitigation stack you inherit automatically:

- **mold linker** (`apt-get install -y mold` step) routes every
  Rust link step through mold instead of `ld.bfd` (~3× less RSS).
- **`[profile.coverage]`** in [`Cargo.toml`](Cargo.toml)
  (`inherits = "dev"`, `debug = 1`, `lto = false`,
  `codegen-units = 16`, `incremental = false`) — purpose-built
  profile for `cargo llvm-cov` runs. Activated via
  `CARGO_PROFILE_DEV_DEBUG=1` + `CARGO_PROFILE_DEV_LTO=false`
  env-var overrides in the workflow (not via `--profile coverage`,
  which would shift artifacts from `debug/` to `coverage/` and
  break the report step).
- **Aggressive runner cleanup** — `sudo rm -rf` 14 pre-installed
  toolchains (dotnet, Android SDK, GHC, CodeQL, ghcup, powershell,
  chromium, boost, node_modules, jvm, microsoft, swift,
  miniconda) + `docker system prune -af --volumes` +
  `apt-get autoremove --purge -y`. Frees ~30 GB before the build.
- **Swap file on `/mnt`** (the ephemeral data disk, ~70 GB free)
  instead of `/` — 8 GB extra virtual memory without eating into
  the root partition where `target/` lives.
- **`actions/checkout@v4`** pinned across all 8 workflows. The
  upstream `actions/checkout@v5` has an intermittent auth-race
  flake under runner-side network load; v4 is the LTS line.
- **`concurrency: cancel-in-progress`** group on both `ci.yml`
  and `coverage.yml` so force-push during PR iteration cancels
  the stale run and frees the runner pool.
- **`--test-threads=1`** on the Code Coverage job (was 2) caps
  memory-parallel test execution under the trimmed profile.

If you fork the repo and run CI on your own GitHub-hosted runners,
these mitigations apply unchanged. If you self-host the runner, you
can relax the cleanup + swap steps once you've sized the host
appropriately (≥ 16 GB RAM + ≥ 50 GB disk recommended for the heavy
gates).

The 13 per-module coverage thresholds (`coverage/thresholds.toml`)
were re-pinned to `floor(measured - 0.5)` post-#1146 to absorb the
~1500 new LOC the enterprise-config campaign landed; future PRs
ratchet UP from those new floors per the standing
thresholds-rise-NEVER-fall discipline.

## Pull Request Process

1. Fork the repository (external contributors) or branch directly (collaborators).
2. Create a feature branch from `develop` (`git checkout develop && git checkout -b feature/my-change`).
3. Make your changes, following the code style and testing guidelines above.
4. Ensure all four gates pass: `cargo fmt`, `cargo clippy -- -D warnings -D clippy::all -D clippy::pedantic`, `AI_MEMORY_NO_CONFIG=1 cargo test`, and `cargo audit`.
5. Push your branch and open a pull request against `develop` (not `main`).
6. Fill out the PR description with what changed and why.
7. Address any review feedback.

**Note:** All PRs target the `develop` branch. The `main` branch is for production releases only — `develop` → `main` merges are done by maintainers when cutting a release.

See the 8-step feature checklist in [DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md) for end-to-end guidance on adding new features.

For the full engineering standards (security review, release process, test protocols), see [ENGINEERING_STANDARDS.md](docs/ENGINEERING_STANDARDS.md). In case of conflict, ENGINEERING_STANDARDS.md is authoritative.

## AI-Assisted Contributions

If you are contributing with the help of an AI coding agent (Claude Code, Cursor, Copilot, Codex, Grok CLI, Gemini CLI, Continue.dev, Windsurf, OpenClaw, or any MCP-compatible client), two additional documents are mandatory reading:

- [`docs/AI_DEVELOPER_WORKFLOW.md`](docs/AI_DEVELOPER_WORKFLOW.md) — the step-by-step workflow every AI session must follow (recall → plan → branch → implement → gates → self-review → PR → handoff).
- [`docs/AI_DEVELOPER_GOVERNANCE.md`](docs/AI_DEVELOPER_GOVERNANCE.md) — the policy boundaries for AI participation: authorized agents, authority classes (Trivial / Standard / Sensitive / Restricted), attribution rules, review requirements, security policy, memory governance, and audit.

Every AI-authored commit must include a `Co-Authored-By:` trailer naming the model and provider. Every AI-authored PR must include the **AI involvement** section described in [`AI_DEVELOPER_WORKFLOW.md` §8.2](docs/AI_DEVELOPER_WORKFLOW.md). The accountable human (the person driving the agent) signs the [CLA](CLA.md) and is responsible for compliance.

Precedence (highest first): `LICENSE`/`CLA.md`/`NOTICE`/`CODE_OF_CONDUCT.md` > [`AI_DEVELOPER_GOVERNANCE.md`](docs/AI_DEVELOPER_GOVERNANCE.md) > [`ENGINEERING_STANDARDS.md`](docs/ENGINEERING_STANDARDS.md) > [`AI_DEVELOPER_WORKFLOW.md`](docs/AI_DEVELOPER_WORKFLOW.md) > this `CONTRIBUTING.md`.

## Commit Message Conventions

Use the following format:

```
<type>: <short summary>

<optional body explaining the change in more detail>
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `perf`.

Examples:

- `feat: add batch memory import from JSONL`
- `fix: prevent duplicate entries during sync`
- `docs: update CLI usage examples`

## Branch Protection & Code Review

The `main` branch is protected. The following rules are enforced:

- **No direct pushes to `main`.** All changes must go through a pull request.
- **Owner approval required.** Every PR to `main` requires approval from `@alphaonedev` (CODEOWNERS). No exceptions.
- **CI must pass.** Both `Check (ubuntu-latest)` and `Check (macos-latest)` status checks must succeed before merge.
- **Stale reviews are dismissed.** If you push new commits after receiving approval, the approval is invalidated and must be re-granted.
- **Force pushes and branch deletion are blocked** on `main`.

PRs to `develop` do not require owner approval but must pass CI (fmt, clippy pedantic, tests). Maintainers merge `develop` into `main` for releases.

## Release Process

1. Version bumps are coordinated by maintainers.
2. A changelog entry is added for every release (see `CHANGELOG.md`).
3. Releases are tagged as `vX.Y.Z` and published from the `main` branch.
4. Crate publishing and binary builds are handled by CI.

## Contributor License Agreement (CLA)

All contributors must agree to the project's [Contributor License Agreement](CLA.md) before their contributions can be accepted. The CLA ensures that you grant AlphaOne LLC the necessary rights to use your contributions under the Apache License, Version 2.0, while you retain ownership of your work.

- **Individual contributors:** Include your signed CLA information (as described in [CLA.md](CLA.md)) in your first pull request.
- **Corporate contributors:** Have your authorized representative submit the Entity CLA before any employees or contractors submit pull requests.

If you have questions about the CLA, open an issue or contact the project maintainers.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License, Version 2.0](LICENSE).
