# W5-A5 — Observability without phone-home (OTel · metrics · SLOs)

**Lens:** ops / procurement / integrity of the *endpoint-resident* claim  
**Question:** Can perfect endpoint memory be operable (alerts, latency, mesh health) without becoming a telemetry product or a silent beacon?  
**Code anchors:** `docs/telemetry.md`, `src/metrics.rs`, `src/logging.rs`, `src/lib.rs` (`/metrics` routes + admission exempt), `PERFORMANCE.md`, `.github/workflows/bench.yml`, ROADMAP §7.6 / §11.6 OTel commitment  
**Ballot role:** phone-home skeptic — pull > push; metadata > content; operator sinks only.

---

## VERDICT

**CONDITIONAL PASS on phone-home discipline today; NOT YET on production-grade observability parity.**

v0.9 ships a **defensible no-phone-home posture**: no OpenTelemetry crates in the tree, no SaaS SDKs, Prometheus is **pull-only**, logs go only to operator sinks (`file` / `stdout` / opt-in `syslog` with explicit address + TLS CA). Spans/metrics are **operation metadata** (counts, durations, peer/result labels) — never memory content, embeddings, or prompts. That is structural to endpoint-resident procurement (`docs/telemetry.md` + ROADMAP “operator-controlled telemetry”).

It is **not** yet a perfect observability substrate:

1. **OTel = commitment only** (v1.0 §11.6) — no OTLP exporter, no semconv span map, no `OTEL_*` surface in code.  
2. **Metrics surface is HTTP-daemon-centric** — scrape at `/metrics` + `/api/v1/metrics`; MCP stdio process has process-local counters but no first-class scrape/export path (partial mirror via `memory_capabilities` for a few hooks).  
3. **SLOs are dual-track and incomplete** — CI/bench budgets in `PERFORMANCE.md` (7/14 rows bench-verified; 10k scale gate exists; 100k still a blind spot for CI) vs runtime Prometheus (strong federation/ops gauges, **sparse latency histograms** — recall + curator cycle only; no store/MCP-tool histograms).  
4. **No packaged alert rules / SLO burn-rate** — metric *comments* define SLOs (cred fail rate, DLQ depth, renewal lag); operators must DIY.

**Perfect-system bar:** local-first observability contracts (semconv spans + Prom series + bench SLOs) with **zero default outbound**, **content-free attributes by CI gate**, and **surface parity** (HTTP scrape + MCP/CLI stats export) so air-gapped fleets are first-class.

---

## CONFIDENCE

**0.84** — phone-home claim verified by absence of OTel deps + telemetry policy + metrics pull design; SLO completeness is an inventory judgment against `PERFORMANCE.md` and `Metrics` field set.

---

## SURFACE MAP (what ships)

| Layer | Mechanism | Destination | Content posture |
|---|---|---|---|
| **Tracing** | `tracing` + subscriber | stderr default; `[logging]` file; `AI_MEMORY_LOG_SINK=stdout\|syslog` | Metadata (`operation`, agent_id, ns, duration, result); **no body** |
| **Anonymize** | `AI_MEMORY_ANONYMIZE=1` | spans only | agent_id redacted externally; DB retains claim for audit |
| **Prometheus** | `src/metrics.rs` → `GET /metrics`, `/api/v1/metrics` | **pull** scrape | counts/histograms/gauges only |
| **Doctor** | `ai-memory doctor` | local (+ LLM/embed probe to **configured** URLs only) | health sections; not a registry phone-home |
| **Bench SLOs** | `ai-memory bench` + `bench.yml` | CI | p95 vs `PERFORMANCE.md` (±10% tolerance); default + `--scale 10000` |
| **OTel / OTLP** | ROADMAP only | — | **not implemented** |

**Representative Prom series (non-exhaustive):** `ai_memory_store_total{tier,result}`, `ai_memory_recall_total{mode}`, `ai_memory_recall_latency_seconds`, `ai_memory_memories`, HNSW size/eviction, webhook + subscription DLQ overflow, curator cycle hist, federation fanout/DLQ/partial-quorum/cred verify & age/renewal lag, `admission_shed_total`, AGE projection depth/fail/quarantine. Label sets are closed enums (cardinality-safe).

**Allowed outbound (not “telemetry”):** federation peers (operator allowlist), embedder/LLM endpoints the operator configured, optional syslog collector when explicitly selected. Unset config ⇒ no beacon.

---

## GAPS

| ID | Gap | Severity |
|---|---|---|
| **O1** | **OTel/OTLP not shipped** — span shape “compatible” in policy only; no exporter, no `OTEL_SERVICE_NAME` wiring, no baggage discipline | High (v1.0 epic) |
| **O2** | **No mechanical CI gate** that spans never log `content`/`title`/embedding payloads (policy + review today; grepable but not hard-block) | Med |
| **O3** | **MCP/CLI observability asymmetry** — no scrape endpoint on stdio MCP; long-lived MCP sessions invisible to Prom unless HTTP co-deployed | Med (ops) |
| **O4** | **Latency histogram sparse** — store path, MCP dispatch, federation RTT, embed/LLM tail not first-class hist series (only recall + curator cycle) | Med |
| **O5** | **Half of PERFORMANCE.md rows advisory** (7/14); cold hybrid / session_start / embed-store / federation ack not CI-gated | Med |
| **O6** | **Corpus-scale CI stops at 10k** — #1579 100k regression class not on default PR gate | Med |
| **O7** | **No reference PrometheusRule / dashboard** for published SLOs (cred fail rate, DLQ depth WARN threshold #84, admission shed, HNSW eviction rate) | Low–Med |
| **O8** | **Scrape auth posture** — `/metrics` is admission-exempt by design; if bind is non-loopback without network policy, series (counts, not content) leak operational intel | Low (ops) |
| **O9** | **Future OTel footgun** — any default `OTEL_EXPORTER_OTLP_ENDPOINT` or vendor SDK would convert endpoint-resident into phone-home | Critical *if* mis-shipped |
| **O10** | **Runtime vs CI SLO disconnect** — bench p95 not mirrored as Prom recording rules; operators cannot alert on the same numbers CI enforces | Med |
| **O11** | **Decorrelation / attestation coverage gauges** incomplete for “enforce diversity” marketing (W3/W4) — observability gap for integrity claims, not just perf | Med (integrity×ops) |

---

## PERF / SLO TRUTH TABLE (short)

| Contract | Enforced where | Status |
|---|---|---|
| Hot recall p95 &lt; 50 ms (default bench) | `bench.yml` + `PERFORMANCE.md` | **Gated** |
| Recall during HNSW rebuild p95 &lt; 35 ms | `hnsw_rebuild_async` bench | **Gated** (release) |
| Scale 10k store/search/recall | `bench --scale 10000` in CI | **Gated** |
| Cold hybrid / session_start / embed store / fed ack | docs only | **Advisory** |
| Federation cred verify fail rate → 0 | metric labels + comments | **Operator DIY** |
| DLQ depth / quarantine-by-cause | gauges + #1544 edge WARN | **Partial** (no shipped alert) |
| Admission shed / AGE lag | counters/gauges | **Partial** |
| OTel export latency / error | — | **N/A** |

---

## VOTE

| Option | Stance |
|---|---|
| **A** — Block any further ship until full in-tree OTel + OTLP | **REJECT** — phone-home discipline already holds; OTel is v1.0 *additive sink*, not a v0.9 integrity hole |
| **B** — Keep no-phone-home; ship OTel only as **opt-in sink**, fail-closed unset endpoint, content-free attributes CI-gated; close O3/O4/O5/O10 before marketing “production observability” | **ACCEPT (majority)** |
| **C** — Default-on OTLP to a vendor or compiled SaaS | **REJECT** — destroys §2.1 endpoint-resident claim |
| **D** — Claim “full OTel + SLO platform” on v0.9 docs | **REJECT** — theater vs code |

**Vote: B.** Observability is a **pull/operator-sink product**. Perfect system adds OTel without ever making export the default path.

**v1.0 must-haves (under B):**  
(1) OTLP exporter **inert unless endpoint set**;  
(2) span attribute allowlist (semconv + closed custom);  
(3) store + MCP tool duration histograms;  
(4) MCP `memory_stats` / capabilities export of core series or a local scrape bridge;  
(5) reference alert rules matching `PERFORMANCE.md` + federation SLOs;  
(6) optional hard gate test: no `content`/`title` in span field names at call sites.

---

## KILLER_OBJECTION

**If observability requires a network path the operator did not name, “endpoint-resident” is marketing.**  
Equally: if OTel lands with **debug spans carrying titles, query text, or embedding norms**, the product becomes a secret-exfil channel dressed as ops. Phone-home is not only “anonymous usage pings” — it is **any default outbound + any content-bearing export**. The substrate’s current strength is *negative space* (no exporter, pull metrics, metadata-only). The killer failure mode is **shipping “industry-standard OTel” the same way SaaS agents do** (always-on collector, rich attributes) and thereby selling the opposite of the procurement claim that differentiates this category (W3-A6).

---

## TOP_RISK

**O9 — OTel implementation that defaults outbound or leaks content.** Secondary: **O3+O10** — operators run MCP-only dogfood, believe “we have metrics/SLOs,” while scrape + runtime burn alerts never see the process; CI green at ≤10k masks 100k recall cliffs until production. Tertiary: unauthenticated `/metrics` on a public bind as free recon of federation health and corpus size.

**Hard stops for claims:**  
- Do **not** claim “OpenTelemetry supported” until OTLP is code + tests + docs with **unset = no dial**.  
- Do **not** claim “SLO-enforced in production” while half of budgets are advisory and no Prom rules ship.  
- Do **not** weaken no-phone-home for “better DX.”

---

## Bottom line

| | |
|---|---|
| **VERDICT** | CONDITIONAL PASS (phone-home); gaps on OTel/SLO completeness |
| **CONFIDENCE** | 0.84 |
| **VOTE** | **B** — opt-in OTel only; close MCP/histogram/bench gaps for perfect ops |
| **KILLER** | Default outbound OTel or content-bearing spans = phone-home theater |
| **TOP_RISK** | Mis-shipped OTel defaults + MCP-blind metrics + advisory SLOs overclaimed |

**Sources:** `docs/telemetry.md`, `src/metrics.rs`, `src/logging.rs`, `PERFORMANCE.md`, `ROADMAP.md` §7.6/§11.6, `waves/w3-a5-timeline.md` item 16.
