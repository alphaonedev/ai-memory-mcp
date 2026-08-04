# Ready-to-tag certification note — ai-memory v1.0.0

**Status:** READY-TO-TAG (operator-gated)  
**Recommended cut tip (current):** `b1bd4c59a84cc864095ab459ee84134e0a621a85` — includes Gate1 residual closes (#2529/#2536/#2532) + release/Docker `--features sal` assert (#2700).  
**First cert-note tip:** `0130b2f191120b1eed49df7ab53403551cfa275c` — first tip that **includes this cert note**.  
**Also valid to cut:** any `release/v1.0.0` tip that is a **descendant of `0130b2f1`** and still contains this file.  
**Do not cut:** `c1c6055d` — measure-binary parent; **omits** this cert note.  
**Measure binary (Gate3):** `c1c6055d` (asserted `sal-postgres` build).  
**Branch:** `release/v1.0.0`  
**Date:** 2026-08-04 (tip-aligned)  
**Epic:** [#2682](https://github.com/alphaonedev/ai-memory-mcp/issues/2682)  
**Authority:** AI NHI 100% engineering; **operator only** for tag cut + publish

## Gates

| Gate | Status | Evidence |
|------|--------|----------|
| **1 Structural confinement** | PASS | `push_lanes` exhaustiveness + shared `inbound_*`; links/signals/crypto lanes; pull path #2480 via #2685 `4dcc6639`; residuals #2529/#2536/#2532 closed (#2694/#2696/#2698) |
| **2 Claims** | PASS | Merge order **#2655 → #2656 → #2668 → #2659 LAST** (… `8a52069a`) |
| **Packaging #2676** | PASS | #2686 `c1c6055d` — `ai-memory features` + `assert-compiled-features.sh`; release/Dockerfile ship `--features sal` + assert |
| **3 Measured evidence** | PASS | DO do-perf: asserted sal-postgres binary @ `c1c6055d`; PG18+AGE+pgvector; hostssl cleartext REFUSED; TLS1.3 verify-full; 20 stores; droplets torn down |
| **4 Agreement vote** | PASS | 3/3 AGREE with residuals (package tip `0130b2f1`) |

## Merge train (selected)

| Merge | Role |
|-------|------|
| #2683 / #2684 | Gate1 push structural + remaining ns |
| #2685 | Gate1 pull #2480 |
| #2655 → #2656 → #2668 → #2659 | Claims train (2659 last) |
| #2686 | Feature self-report |
| #2687 | Ready-to-tag cert note (first tip `0130b2f1`) |
| #2694 / #2696 / #2698 | Gate1 residuals #2529 / #2536 / #2532 |
| #2700 | Release/Docker ship `--features sal` + assert |

## Explicit residual list (must appear on any tag checklist)

### Gate1 confinement residuals (open issues)
**None remaining.** All tracked Gate1 confinement residuals closed this train:

- **#2529** via #2694 (`2a74c800`) — refuse wire non-pending + local terminal; upsert never overwrites decision cols
- **#2536** via #2696 (`9d06e728`) — namespace_meta requires descendant tree-coverage probe
- **#2532** via #2698 (`54203b22`) — REJECT namespace-confined same as APPROVE (closes unauthorized foreign veto)

### Packaging / release-channel residual
5. **Release channel ships `--features sal`** (Dockerfile + `release.yml` matrix) and asserts via `scripts/assert-compiled-features.sh` (`sqlite-bundled` + `sal`). **`sal-postgres` is not** on every multi-OS release binary (native sqlx weight); PG deployments use an asserted `sal-postgres` build (Gate3 measure tip `c1c6055d` / plan-c image). Operators still verify cut artifacts with `ai-memory features` / assert script before publish.

### Capacity / follow-on (not gate-blocking for this cert claim set)
6. **Landed capacity (inventory at tip):** #2643 (`30cc680d0b28`, authz #2538/#2633); #2689 (`fd7866120c52`, signed re-land of #2644 bulk funnel); #2662 (`44410b195331`, delete-lane DLQ #2498); #2663 (`105526746191`, /sync/since cursor #2441); #2673 (`a9d62550`, erasure outbox #2446).
   **Capacity train complete** — no open capacity PRs remain for this residual set.

### Scale claim residual
7. **No 1M+ agent scale certification**; modular 500–1000 claim envelope only as previously published after claims corrections.

## Operator actions (only)

1. Review this note + residual list  
2. Optionally land residual security issues or accept as post-tag  
3. **Cut** `v1.0.0` on recommended tip **`b1bd4c59`** (or any later descendant that still contains this document; minimum ancestor `0130b2f1`) — **never** on `c1c6055d`  
4. **Dispatch** publish workflows  
5. Agents **must not** create tags or dispatch release/publish

## Verification commands (reproduce)

```bash
git fetch origin && git log -1 --oneline origin/release/v1.0.0
# recommended: b1bd4c59 or descendant; must include this file (never cut c1c6055d)
git merge-base --is-ancestor 0130b2f1 origin/release/v1.0.0 && echo "cert-note tip is ancestor of HEAD: OK"
git merge-base --is-ancestor b1bd4c59 origin/release/v1.0.0 && echo "recommended cut tip is ancestor of HEAD: OK"
git tag -l 'v1.0.0*'   # expect empty until operator cuts
# release channel (GHCR/deb/tarball):
cargo build --release --features sal
./target/release/ai-memory features
scripts/assert-compiled-features.sh ./target/release/ai-memory --require sqlite-bundled --require sal
# Gate3 PG measure path (optional reproduce):
cargo build --release --features sal-postgres
scripts/assert-compiled-features.sh ./target/release/ai-memory --require sal-postgres
```

## Dual-checkpoint
ai-memory namespace `ai-memory` tags `checkpoint,epic-pointer,rolling` updated through this beat.
Engineering campaign complete for ready-to-tag; operator owns tag cut + publish.
