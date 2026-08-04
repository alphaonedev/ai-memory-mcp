# Ready-to-tag certification note — ai-memory v1.0.0

**Status:** READY-TO-TAG (operator-gated)  
**Tip SHA:** `d742f3314860e199a75c257c554835dabddef1b0`  
**Branch:** `release/v1.0.0`  
**Date:** 2026-08-04T01:43:35Z  
**Epic:** [#2682](https://github.com/alphaonedev/ai-memory-mcp/issues/2682)  
**Authority:** AI NHI 100% engineering; **operator only** for tag cut + publish  

## Gates

| Gate | Status | Evidence |
|------|--------|----------|
| **1 Structural confinement** | PASS with residuals | `push_lanes` exhaustiveness + shared `inbound_*`; links/signals/crypto lanes; pull path #2480 via #2685 `a9b77b24` |
| **2 Claims** | PASS | Merge order **#2655 → #2656 → #2668 → #2659 LAST** (… `f95d889e`) |
| **Packaging #2676** | PASS with residual | #2686 `d742f331` — `ai-memory features` + `assert-compiled-features.sh` |
| **3 Measured evidence** | PASS | DO do-perf: asserted sal-postgres binary; PG18+AGE+pgvector; hostssl cleartext REFUSED; TLS1.3 verify-full; 20 stores; droplets torn down |
| **4 Agreement vote** | PASS | `{SCRATCH}/gate4-vote.md` — 3/3 AGREE with residuals |

## Merge train (selected)

| Merge | Role |
|-------|------|
| #2683 / #2684 | Gate1 push structural + remaining ns |
| #2685 | Gate1 pull #2480 |
| #2655 → #2656 → #2668 → #2659 | Claims train (2659 last) |
| #2686 | Feature self-report |

## Explicit residual list (must appear on any tag checklist)

### Gate1 confinement residuals (open issues)
1. **#2504** — malformed `AI_MEMORY_FED_PEER_ATTESTATION` character can disable federated-delete ns gate; WARN misstates default-deny for that lane  
2. **#2529** — federated `pendings[]` upsert can resurrect decided pending / overwrite decided_by  
3. **#2536** — federated `namespace_meta` at in-scope ancestor can set governance default of out-of-scope descendants  
4. **#2532** — federated REJECT of foreign-namespace pending is unauthorized veto (deliberately ungated by #2478)

### Packaging / release-channel residual
5. **Release.yml / Dockerfile default feature set** may still omit `sal` / `sal-postgres` — certification measured an **asserted** feature build; operators must not tag without verifying release artifact features via `ai-memory features` / assert script.

### Capacity / follow-on (not gate-blocking for this cert claim set)
6. Open capacity PRs may remain: #2643, #2644, #2662, #2663, #2673 (security/data integrity capacity — land as capacity allows; not required to assert “ready-to-tag under residual list” if residual list is honest).

### Scale claim residual
7. **No 1M+ agent scale certification**; modular 500–1000 claim envelope only as previously published after claims corrections.

## Operator actions (only)

1. Review this note + residual list  
2. Optionally land residual security issues or accept as post-tag  
3. **Cut** `v1.0.0` tag on tip `d742f331` if satisfied  
4. **Dispatch** publish workflows  
5. Agents **must not** create tags or dispatch release/publish

## Verification commands (reproduce)

```bash
git fetch origin && git log -1 --oneline origin/release/v1.0.0
# expect d742f331
git tag -l 'v1.0.0*'   # expect empty until operator cuts
cargo build --release --features sal-postgres
./target/release/ai-memory features
scripts/assert-compiled-features.sh ./target/release/ai-memory --require sal-postgres
```

## Dual-checkpoint
ai-memory namespace `ai-memory` tags `checkpoint,epic-pointer,rolling` updated through this beat.
