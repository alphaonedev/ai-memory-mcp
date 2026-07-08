# W5-A4 — Mobile / IoT / Robotics Floor

> **Agent:** W5-A4 (Mobile/IoT/robotics floor · §2.1 physics)  
> **Date:** 2026-07-08  
> **Lens:** Endpoint residency at the silicon/energy/size floor — phones, Pi-class boards, robotics controllers, Tier ∅ MCUs  
> **North Star:** ROADMAP §2.1 · §25.8 endpoint tiering · TRACT §10 · `docs/mobile-iot-deployment.md`  
> **Prior votes:** Red Queen Agent 12 · D-OPUS-5 · W3-A4 (wrappers OUT / FFI IN)

---

## VERDICT

**§2.1 holds at a *tens-of-MB* floor (phones, Pi/robotics Linux, Jetson-class), not at kilobyte-RAM MCUs.** The honest product floor is:

| Claim | Reality |
|---|---|
| “Runs at every endpoint” | **PASS** for Cortex-A-class and above with ~31 MB binary / ~18–25 MB idle RSS |
| “IoT sensors with kB of RAM” (pre-D-OPUS-5 moonshot) | **REFUTED ~1000×** — Tier ∅ does **not** host L1 |
| Mobile CI / artifacts as §2.1 evidence | **PASS for compile+link+sim** — **PARTIAL for callable host surface** (FFI still stub-level) |
| Robotics / field drone / auto head-unit | **PASS as topology** (local SoR + opportunistic hub sync) when Linux/Android A-class |

**Ballot:** AFFIRM the measured tier model (∅/A/B/C); REJECT any procurement claim that ai-memory is a bare-metal MCU library; TREAT C-ABI completion as **P1 substrate**, full language SDKs as **post-GA / out**.

**CONFIDENCE:** **0.88**

---

## TIER_MODEL

Canonical physical residency (TRACT-2026 instantiation; law is silicon-independent — cost-of-access gradient, not nameplate bytes baked into L1).

```
TIER C  Fleet / swarm hub          L1+L2+L3-export · postgres SAL · curator · decorrelation
TIER B  Pi / Jetson / phone daemon L1+L2 light · sqlite MCP/HTTP · reflect DEFER-or-hub
TIER A  Field phone / sensor edge  L1 ONLY · keyword · ephemeral CLI · store/recall/sync
TIER ∅  MCU / Zephyr / NuttX       ai-memory NOT resident · gateway holds L1
```

### Measured floor numbers (operator SSOT)

Source: `docs/mobile-iot-deployment.md` §6–§9 (Cortex-A72 class).

| Resource | Floor / band |
|---|---|
| Binary (strip + thin LTO) | **~31 MB** |
| Idle daemon RSS | **~18–25 MB** |
| Recall load (10k vec, 384-d) | **~80–120 MB** |
| + MiniLM embedder | **+250–400 MB** → drop via `keyword` tier |
| Disk / 1k memories | **~6 MB** |
| Keyword FTS p95 (10k) | **~3 ms** |
| Semantic p95 (10k) | **~25–40 ms** (A72; 1.5–2.5× vs A76/M2 class) |

### Auto tier by memory budget

`FeatureTier::from_memory_budget` (`src/config.rs`):

| Host RAM budget | Tier | Edge implication |
|---|---|---|
| `<256 MB` | **Keyword** | L1 FTS only; no embedder/LLM on-device |
| `≥256` | Semantic | HNSW + embed cost |
| `≥1024` | Smart | LLM surfaces viable |
| `≥4096` | Autonomous | Full local stack |

**Tier A law:** no on-device curator, no decorrelation write-gate, no RQGM. Reflect / atomise / consolidate / heavy KG → **hub**. Edge surface = `store` · FTS `recall`/`search` · gate · attest · `/sync/push` + `/sync/since` · `--profile core` + `--tier keyword` when constrained.

### Run-mode matrix (robotics / IoT)

| Device | Mode | Tier |
|---|---|---|
| Phone active chat | daemon | semantic |
| Pi 4/5 mains | daemon | semantic |
| Pi Zero / battery sensor | ephemeral CLI | keyword |
| Drone waypoint memory | ephemeral | keyword→semantic if Jetson |
| Wearable / MCU | thin client → phone/gateway L1 | n/a (Tier ∅) |
| Auto head-unit Android | embed cdylib / daemon | semantic |

### CI / artifact floor (shipped)

| Layer | Gate | Status |
|---|---|---|
| 1 Cross-compile | `mobile-cross-compile` every PR | GREEN contract |
| 2 Release art | `mobile-ios` / `mobile-android` | xcframework + jniLibs |
| 3 Runtime | `mobile-runtime.yml` on `release/**` | ~50 tests: sandbox, FTS5+WAL, HNSW CPU, embedder CPU, TLS |
| FFI | `ai_memory_version` only (`src/lib.rs` ARCH-10) | **Stub header** until #1068 Layer 2 full C-ABI |
| Codesign | consumer-signs-at-integration | Producer attest = follow-up |

Wrappers (Swift/Kotlin/RN) stay **OUT** (W3-A4); **C-ABI/staticlib/cdylib IN**.

---

## GAPS

| ID | Gap | Severity | Why it matters at §2.1 |
|---|---|---|---|
| **G1** | Full C-ABI surface incomplete (version-only) | **P1** | Linkable artifact without store/recall/verify symbols = host-integration theater on pure mobile |
| **G2** | No mechanical **capability manifest** per tier (what this endpoint *cannot* attest) | **P1** | TRACT §10 requirement; without it, Tier A looks like “full product” in marketing |
| **G3** | RISC-V / armv7 prebuilts + CI weak/absent | **P2** | Community-attested only; industrial IoT often non-AArch64-first-class |
| **G4** | Android runtime arm push-gated; producer supply-chain attest soft | **P2** | Sim ≠ fleet silicon; unsigned release tarballs rely on consumer codesign only |
| **G5** | FFI/process lifecycle under iOS suspension / Android battery kill not fully exercised | **P2** | Robotics + phone background are the real failure modes |
| **G6** | Gateway-held L1 for Tier ∅ has no typed protocol (BLE/LoRa → phone) in-tree | **P2** | Correct architecture, under-specified wire contract |
| **G7** | Docs residual: `moonshot-synthesis.md` may still carry kB phrasing vs ROADMAP correction | **P2** | Re-opens D-OPUS-5 overclaim if procurement reads moonshot alone |
| **G8** | On-device multi-ASI decorrelation **impossible** at Tier A (no LLM) | **By design** | Must not be sold as §2.6-complete at field edge — hub owns that property |

**Not gaps (affirm as cuts):** full SDK product surface; in-tree RQGM; cloud SaaS memory; MCU-native full substrate.

---

## VOTE

| Motion | Vote |
|---|---|
| Affirm real floor ≈ **31 MB binary / 18–25 MB idle RSS** | **YES** |
| Affirm Tier ∅ = **gateway-held L1 only** (no MCU port of full daemon) | **YES — eternity** |
| Affirm Tier A = **L1-only** (keyword/ephemeral; heavy ops hub) | **YES** |
| Affirm mobile CI Layers 1–3 as **necessary** §2.1 evidence | **YES** |
| Treat current mobile ship as **§2.1 compile/runtime floor PASS** | **CONDITIONAL YES** (G1 C-ABI) |
| Claim “kilobyte IoT sensors run ai-memory” | **NO** |
| Ship full Swift/Kotlin/RN wrappers in monorepo pre-GA | **NO** (W3-A4) |
| Complete C-ABI store/recall/attest/verify as substrate P1 | **YES** |
| Publish per-tier **cannot-attest** capability manifest | **YES** |
| Require producer SLSA/attest on mobile artifacts | **YES** (P2, not end-user trust anchor) |
| Grade ASI moonshot on pure edge silicon alone | **B / B+** capped — floor physics soft if sold as universal endpoint |

**Ballot summary:** Physics-honest tiering is the floor product. Expand **callable edge surface** and **tier manifests**; do not expand **MCU residency claims**.

---

## KILLER

**“If the moonshot is governance at every point cognition meets reality, a ~20 MB RSS floor leaves trillions of sensors and actuators outside the TCB — so §2.1 fails.”**

**Kill:** §2.1 is **custody of L1 at the light-cone boundary of decision**, not **bit-for-bit residency on every transistor**. Tier ∅ actuators that cannot store law still emit **signed observations** into a nearby phone/gateway that *is* the endpoint of record. Collapsing “endpoint” to “MCU flash” confuses **sensor physics** with **governance physics** and forces a product that cannot host SQLite, Ed25519 audit, or fail-closed refuse. Perfect systems are **tiered federations of roles**; the floor is the smallest host that can still **attest, refuse, and sync**, with thinner devices as clients of that floor.

---

## TOP_RISK

**Marketing floor drift: “mobile/IoT ready” read as MCU-ready + full governance.**  
Selling the xcframework/cdylib + Termux recipes as proof that *every* field device runs attested multi-ASI memory reintroduces the D-OPUS-5 ~1000× overclaim and invites procurement theater. Mitigations: keep ROADMAP/moonshot wording aligned; ship **Tier ∅/A/B/C capability manifests** on boot/`memory_capabilities`; finish **C-ABI** so mobile hosts exercise real L1 verbs; never claim §2.6/curator completeness on keyword Tier A.

**Secondary:** Incomplete FFI (G1) leaves iOS/Android integrators on Termux/sidecar only — endpoint-resident fails for pure-app hosts until Layer 2 lands.

---

*Agent W5-A4 · Mobile/IoT/robotics floor · under 250 lines*  
*Path: `/Users/fate/Downloads/ai-memory-mcp/waves/w5-a4-mobile-iot.md`*
