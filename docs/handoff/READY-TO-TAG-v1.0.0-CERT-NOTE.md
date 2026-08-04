# Ready-to-tag certification note — ai-memory v1.0.0

**Status:** READY-TO-TAG (operator-gated)  
**Tip SHA (cut target):** `b95ad9780585e6a7354f9ae994e0d95829913567` — first tip that **includes this cert note**.  
**Also valid to cut:** any later `release/v1.0.0` tip that is a **descendant of `b95ad978`** and still contains this file (e.g. tip-alignment edits).  
**Do not cut:** `d742f331` — measure-binary parent; **omits** this cert note.  
**Measure binary (Gate3):** `d742f331` (asserted `sal-postgres` build).  
**Branch:** `release/v1.0.0`  
**Date:** 2026-08-04T01:50:00Z  
**Epic:** [#2682](https://github.com/alphaonedev/ai-memory-mcp/issues/2682)  
**Authority:** AI NHI 100% engineering; **operator only** for tag cut + publish

## Gates

| Gate | Status | Evidence |
|------|--------|----------|
| **1 Structural confinement** | PASS with residuals | `push_lanes` exhaustiveness + shared `inbound_*`; links/signals/crypto lanes; pull path #2480 via #2685 `a9b77b24` |
| **2 Claims** | PASS | Merge order **#2655 → #2656 → #2668 → #2659 LAST** (… `f95d889e`) |
| **Packaging #2676** | PASS with residual | #2686 `d742f331` — `ai-memory features` + `assert-compiled-features.sh` |
| **3 Measured evidence** | PASS | DO do-perf: asserted sal-postgres binary @ `d742f331`; PG18+AGE+pgvector; hostssl cleartext REFUSED; TLS1.3 verify-full; 20 stores; droplets torn down |
| **4 Agreement vote** | PASS | 3/3 AGREE with residuals (package tip `b95ad978`) |

## Merge train (selected)

| Merge | Role |
|-------|------|
| #2683 / #2684 | Gate1 push structural + remaining ns |
| #2685 | Gate1 pull #2480 |
| #2655 → #2656 → #2668 → #2659 | Claims train (2659 last) |
| #2686 | Feature self-report |
| #2687 | Ready-to-tag cert note (tip becomes `b95ad978`) |

## Explicit residual list (must appear on any tag checklist)

### Gate1 confinement residuals (open issues)
1. **#2504** — malformed `AI_MEMORY_FED_PEER_ATTESTATION` character can disable federated-delete ns gate; WARN misstates default-deny for that lane  
2. **#2529** — federated `pendings[]` upsert can resurrect decided pending / overwrite decided_by  
3. **#2536** — federated `namespace_meta` at in-scope ancestor can set governance default of out-of-scope descendants  
4. **#2532** — federated REJECT of foreign-namespace pending is unauthorized veto (deliberately ungated by #2478)

### Packaging / release-channel residual
5. **Release.yml / Dockerfile default feature set** may still omit `sal` / `sal-postgres` — certification measured an **asserted** feature build; operators must not tag without verifying release artifact features via `ai-memory features` / assert script.

### Capacity / follow-on (not gate-blocking for this cert claim set)
6. **Landed capacity (tip `3bd01c32` and ancestors):** #2643 (`8aa83e6f`, closes #2538/#2633); #2689 signed re-land of #2644 bulk funnel (`9136b5a3`, closes #2550–#2552/#2588/#2594); #2662 delete-lane DLQ (`3bd01c32`, closes #2498).  
   **Still open (optional before cut):** #2663 (`/sync/since` cursor), #2673 (erasure outbox). Not required to assert ready-to-tag if this residual list is honest.

### Scale claim residual
7. **No 1M+ agent scale certification**; modular 500–1000 claim envelope only as previously published after claims corrections.

## Operator actions (only)

1. Review this note + residual list  
2. Optionally land residual security issues or accept as post-tag  
3. **Cut** `v1.0.0` on tip **`b95ad978` or any descendant on `release/v1.0.0` that still contains this document** — **never** on `d742f331`  
4. **Dispatch** publish workflows  
5. Agents **must not** create tags or dispatch release/publish

## Verification commands (reproduce)

```bash
git fetch origin && git log -1 --oneline origin/release/v1.0.0
# tip must be b95ad978 or a descendant that includes this file (never cut d742f331)
git merge-base --is-ancestor b95ad978 origin/release/v1.0.0 && echo "cert-note tip is ancestor of HEAD: OK"
git tag -l 'v1.0.0*'   # expect empty until operator cuts
cargo build --release --features sal-postgres
./target/release/ai-memory features
# expect features list to include sal-postgres (and sal, sqlite-bundled on default+sal-postgres builds)
scripts/assert-compiled-features.sh ./target/release/ai-memory --require sal-postgres
```

## Dual-checkpoint
ai-memory namespace `ai-memory` tags `checkpoint,epic-pointer,rolling` updated through this beat.
