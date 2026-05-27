# ARCH-6 — Dep-graph duplicate audit (v0.7.0, FX-C4-batch2)

**Status:** AUDITED — every remaining duplicate is upstream-pinned.
**Last verified:** 2026-05-26 against base SHA `54713024d`.

The v2 ARCH lane review (ARCH-6) surfaced 12 duplicate dep versions
in the v0.7.0 dependency tree. `cargo update` was attempted in
FX-C4-batch2 — it consolidated zero of the duplicates because every
remaining duplicate is pinned via a transitive `Cargo.toml`
dependency in an upstream crate we do not control.

## Current duplicate inventory (audited)

| Crate | Versions | Upstream pins (consumers) | Remediation path |
|---|---|---|---|
| `base64` | v0.13.1 + v0.22.1 | `tokenizers` 0.22 → `spm_precompiled` 0.1.4 → `base64` v0.13.1; rest of tree → v0.22.1 | Upstream fix at `spm_precompiled`; non-trivial |
| `bit-set` / `bit-vec` | v0.5.3+v0.8.0 / v0.6.3+v0.8.0 | `petgraph` 0.6 vs newer | Upstream `petgraph` version unification |
| `fancy-regex` | v0.13.0 + v0.17.0 | `tokenizers` 0.22 vs `candle-transformers` 0.10.2 | Upstream version bump |
| `foldhash` | v0.1.5 + v0.2.0 | hashbrown transitives | Upstream sweep |
| `hashbrown` | v0.14.5 + v0.15.5 + v0.16.1 + v0.17.1 | sqlx + candle + native rust + axum | 4-way transitive; upstream |
| `getrandom` | v0.2.17 + v0.3.4 + v0.4.2 | rand-* + reqwest transitives | Upstream sweep |
| `hashlink` | v0.9.1 + v0.10.0 | rusqlite vs sqlx | Upstream version unification |
| `itertools` | v0.10.5 + v0.14.0 | candle-* vs newer | Upstream version bump |
| `rand` / `rand_chacha` / `rand_core` | v0.8.6+v0.9.4 paired | rand-* transitives | rand 0.9 ecosystem rollout |
| `rustix` | v0.38.44 + v1.1.4 | older tokio path + newer io-uring path | Upstream tokio version bump |
| `thiserror` | v1.0.69 + v2.0.18 | `prometheus` 0.13.4 + `gemm-common` 0.19.0 → v1; our own code → v2 | Upstream `prometheus` + `gemm-common` |
| `webpki-roots` | v0.26.11 + v1.0.7 | rustls transitives | Upstream rustls sweep |

## Why this is recorded as `AUDITED` rather than `BLOCKED-WITH-REASON`

Every duplicate above has a concrete upstream-side resolution path
(file an issue / PR against the upstream crate; bump our direct
dep when the upstream landing ships). Our remediation work for
v0.7.0 stops at the inventory — bumping our direct deps was tried,
it does not help.

The first-party action we CAN take is preventing regressions:

1. Keep this audit file in lockstep with `cargo tree -d` output
   at every release.
2. Land a CI guard that fails on a NET-NEW duplicate (proposal
   tracked as a follow-up; not in scope for this batch).
3. When a downstream `chore(deps)` PR lands a clean upstream
   bump, walk the matrix above and confirm the duplicate cleared.

## How to re-verify

```bash
cargo tree -d 2>&1 | grep -E "^[a-z]"   # canonical drift detector
cargo tree -i thiserror:1.0.69          # who pulls a specific dup
```

When a row above clears (the `cargo tree -d` output stops listing
the dup), drop the row from this matrix in the same commit that
bumps the upstream dep. Keep the audit file authoritative.

## Lineage

- Original ARCH-6 finding:
  `.local-runs/reviews-2026-05-26-v2/ARCH-findings.md`.
- FX-C4-batch1 batch left this as a residual.
- FX-C4-batch2 closes by establishing the audit + remediation
  matrix above. The `[Unreleased]` CHANGELOG entry notes the
  audit.
