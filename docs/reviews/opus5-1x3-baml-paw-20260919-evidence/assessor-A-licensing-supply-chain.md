# Independent assessment — BAML and PAW (ProgramAsWeights)

**Assessor A** — emphasis: **licensing and supply chain**. 2026-09-19.
Tree assessed: `/home/fate_two/v07/v09-dev` @ `8b4f65a22` (`release/v1.0.0`).
Rust analysis grounded in the `rust-1.98` standard (`/home/fate_two/.claude/skills/rust-1.98/SKILL.md`); rules cited inline.
Method: sources fetched directly; codegraph CLI for all code claims. Nothing installed, nothing downloaded, no third-party code run.

---

## 1. Votes

| Project | Vote | One-line reason |
|---|---|---|
| **BAML** | **WATCH** | Apache-2.0 and clean at the source level, but the *only* Rust integration path auto-downloads a native dylib from GitHub releases at runtime by default, and the headline tracing claim is an unreproduced vendor number whose only documented sink is a hosted SaaS gated on `BOUNDARY_API_KEY`. |
| **PAW (ProgramAsWeights)** | **REJECT** (for v1.0.0 / v1.1.0) | **Not one of the seven published model artefacts carries a licence.** No licence = no grant = all rights reserved. Separately: the Rust implementation is an unaffiliated 2-star hobby crate, and the hosted API's user prompts are republished as a public Hugging Face dataset. |

Separable side-finding, not a vote: **type-definition prompting is free to take and requires no dependency.** See §2.6.

---

## 2. BAML

### 2.1 What it is

A DSL + compiler for typed LLM functions. Rust core under `engine/` (26 sub-crates incl. `baml-compiler`, `baml-runtime`, `baml-vm`, `baml-schema-wasm`, `llm-response-parser`), generating typed clients for Python / TS / Ruby / Go, plus a Rust consumer path. 9.2k stars, ~3,944 commits on `canary`.

### 2.2 Licence findings — **clean at source, with one unexamined corner**

| Artefact | Licence | Evidence |
|---|---|---|
| Repository root `LICENSE` | **Apache-2.0**, stock, unmodified, no added clauses, no copyright line filled in | fetched `raw.githubusercontent.com/BoundaryML/baml/canary/LICENSE` |
| `engine/LICENSE` | **Apache-2.0**, stock, identical — **no** Elastic/BSL/source-available carve-out for the engine | fetched `.../canary/engine/LICENSE` |
| crates.io `baml`, `baml-sys`, `baml-macros`, `baml-cli` @ 0.221.0 | **Apache-2.0** (`license = { workspace = true }` resolving to Apache-2.0) | crates.io API |
| crates.io `baml_bridge` @ 0.20.1-nightly.20260918.a | **Apache-2.0** | crates.io API |
| Crate ownership | `hellovai` (BAML founder) + `2kai2kai2` — **official, not a squat** | `/api/v1/crates/baml_bridge/owners` |
| `engine/vendored/` | **NOT ESTABLISHED.** A vendored-third-party directory exists; I did not enumerate its contents or per-file licences. Flagging as an open item, not a defect. | directory listing only |
| Boundary Studio (hosted) | **NOT ESTABLISHED.** No ToS or pricing page could be located; search returned only third-party review sites. Pricing for the cloud product is announced-but-unpriced. | web search, 2026-09-19 |

**Verdict on licence: BAML the code is genuinely Apache-2.0 and compatible with our Apache-2.0 + NOTICE + CLA posture (`/home/fate_two/v07/v09-dev/LICENSE`, `/home/fate_two/v07/v09-dev/NOTICE`).** The licence is not the problem. The acquisition mechanism is.

### 2.3 Supply chain — **the finding that decides this**

`baml-sys` is not a normal Rust crate. From its own manifest and README (docs.rs source view, v0.221.0):

```toml
[features]
default = ["download"]
# Enable automatic download from GitHub releases
download = []
# Disable download (for air-gapped environments)
no-download = []
```

Library resolution order, verbatim from the crate README: (1) `baml_sys::set_library_path()`, (2) `BAML_LIBRARY_PATH`, (3) `~/.cache/baml/libs/{VERSION}/`, (4) **"From GitHub releases (if `download` feature enabled)"**, (5) system paths. Runtime deps include `libloading` (dlopen) and `ureq` (HTTP). `build.rs` is a no-op stub that exists only to satisfy the `links` key.

So: **adding `baml` to `Cargo.toml` with default features gives you a crate that will reach out to the public internet at *runtime* and `dlopen` a native shared object it just fetched.** Consequences against this repo specifically:

1. **It is an egress lane that does not exist in our taxonomy.** `src/egress.rs:69` `EgressClass` enumerates exactly five lanes — `Webhook`, `Federation`, `ForensicExport`, `InferenceLlm`, `InferenceEmbedding` — and the doc comment asserts "the taxonomy is complete for audit / documentation purposes." A dylib fetch is a sixth lane, ungoverned by `evaluate_inference_egress`, invisible to the signed refusal row, and not covered by `AI_MEMORY_INFERENCE_EGRESS`. Under posture 2 (air-gapped, `deny`) per `/ai-scratch/conductor/handoff/3806-REQUIREMENTS.md` §2, the process would still try to fetch. That is a **non-fail-closed** path in a product whose egress resolver deliberately fails closed on a *typo* (`src/egress.rs:177` `resolve_inference_egress_mode` → `InferenceEgressMode::Deny` on an unrecognised token).
2. **It defeats the SBOM.** `.github/workflows/release.yml:546` documents the CycloneDX SBOM as enumerating "every resolved dependency in Cargo.lock (name, version, purl, declared license)". A dylib acquired at runtime from GitHub releases appears in **no** `Cargo.lock` and therefore in **no** SBOM component list. The single largest unit of executable code in the integration would be the one unit the bill of materials does not mention.
3. **It is the `vectorlite` plan-killer, verbatim.** `/home/fate_two/v07/v09-dev/Cargo.toml` already records the ruling for exactly this shape: an Apache-2.0 native library with no Rust crate "cannot be acquired reproducibly across the 3-OS CI matrix + 5 release channels, which is the plan-killer #1860 itself documents." `baml-sys` is the same problem with an auto-downloader bolted on. Disabling the downloader (`default-features = false`, or `BAML_LIBRARY_DISABLE_DOWNLOAD=true`) does not solve it — it returns you to #1860's unsolved acquisition problem across six platform targets.
4. **Digest verification: partially established, and the documentation is worse than the code.** `baml-sys` declares `sha2` and `hex` as runtime dependencies, which strongly implies the downloader does verify a digest. But **the README documents no checksum step at all**, and I did not read the download implementation. Stated plainly: *I could not confirm whether the auto-downloaded dylib is digest-verified.* Given `src/inference/mod.rs:263` `verify_attested_weights` refuses to serve from a weight file whose SHA-256 does not match and **fails CLOSED when a signature is present but no operator key resolves** (#654), an undocumented verification story for a native code object is not acceptable without reading that code.
5. **`links = "baml"` + documented global state in the dylib** means exactly one `baml-sys` version per process tree, forever. A future transitive dependency on a different major would be an unresolvable conflict.

Positive note: upstream *names* the concern — the feature is literally commented `# Disable download (for air-gapped environments)`. They know. It is just not the default.

### 2.4 Dependency weight and exit cost

- Direct deps of `baml` 0.221.0: **12** (`async-channel`, `baml-macros`, `baml-sys` ×2, `futures-util`, `libc`, `once_cell`, `prost`, `prost-build`, `serde`, `serde_json`, `thiserror`). Modest — and `serde`/`serde_json`/`thiserror`/`once_cell`/`libc`/`futures-util` are already in our tree.
- **New build-toolchain burden:** `prost-build` 0.13 pulls protobuf codegen into the build graph. That is a new build-time requirement on a 3-OS CI matrix, plus `async-channel` and `prost` as genuinely new direct deps.
- **Maintenance signal is mixed and worth watching:** the stable `baml` crate's last release is **0.221.0, 2026-04-15 — five months stale**, while `baml_bridge` (created 2026-07-15, "embeds the BAML engine behind generated, typed SDKs", 1,270 downloads) is shipping *nightly* builds, latest **0.20.1-nightly.20260918.a dated 2026-09-19**. Read plainly: the Rust surface is mid-rearchitecture and the version we would pin is the one they have stopped shipping. Total Rust adoption is small — `baml` 12,183 all-time downloads.
- **Exit cost: LOW-to-MODERATE, *if* it is confined behind `InferenceBackend` (`src/inference/mod.rs:85`) or the `[decision]` provider slot.** Our architecture is already built for swapping deciders, so a regretted BAML would be a provider deletion, not a refactor. The non-recoverable part is the dylib-acquisition plumbing in CI and packaging — that is where the sunk cost would sit.

### 2.5 The tracing claim — what is claim, what is verified

- **Vendor claim, confirmed to exist on boundaryml.com and nowhere else:** tracing "6x faster than OpenTelemetry in Rust, 200x faster in Python, and the traces 1000x smaller", tracing every function rather than sampling. The Conductor's note holds: **it is not in the GitHub README and I found no published methodology.** Unreproduced. Treat as marketing.
- **Verified and decisive for us:** the documented destination for those traces is **Boundary Studio, a hosted SaaS**. Verbatim from `docs.boundaryml.com/guide/boundary-cloud/observability/tracking-usage`: *"To enable observability with BAML, sign up for a Boundary Studio account"*; *"Logs are only sent to the Dashboard if you setup `BOUNDARY_API_KEY` environment variable"*; Studio can "represent your traces as functions, with typed parameters, **inputs and outputs**." **No OTLP export and no self-hosted collector are documented.** `BOUNDARY_API_URL` is overridable, but the wire format is Boundary's own batched-gzip protocol, not OTLP — pointing it at our own endpoint means writing a receiver for an undocumented proprietary format.
- **Therefore the thing the operator is interested in is the one part that is not a local library.** Piloting the tracing claim requires a Boundary account and shipping trace payloads containing prompt inputs and completions — i.e. **memory content** — to a third party. That collides head-on with the brief's own hard rule and with `src/egress.rs`. And "1000x smaller" almost certainly compares gzipped compact frames against OTLP JSON; that is a compression comparison wearing a tracing costume until a methodology says otherwise.
- **What we already have:** `src/metrics.rs:1418` `render()` is a `prometheus::TextEncoder` over a process-global `OnceLock<Metrics>` registry (`src/metrics.rs:487`), with a documented graceful-degradation contract ("returns an empty string — the scrape returns 200 with a possibly-empty body rather than a 5xx"). Note for the Conductor: **I could not find a 64 KiB cap on the `/metrics` renderer** — `render()` as written is unbounded, and a grep for `65536` / `METRICS_MAX` / "64 KiB" in `src/` found nothing. If that cap is believed to exist, it does not exist at this commit. Flagging as a possible stale premise in the brief, or a real gap.

### 2.6 Type-definition prompting — **separable, and that changes everything about the cost side**

The operator's second source (`boundaryml.com/blog/type-definition-prompting-baml`) is more testable than the tracing claim, and my answer to the specific question is unambiguous:

**Yes, the idea and the product are fully separable. Nothing in the licence or the positioning binds them.**

- **No patent is claimed.** The post makes no patent, trademark or licensing claim over the technique. The surrounding code is Apache-2.0, which grants a patent licence anyway (Apache-2.0 §3) — so even if a patent existed and read on their implementation, use of *their* code would be licensed. But we would not be using their code.
- **Extensive prior art, predating BAML, makes any exclusivity claim implausible.** Microsoft **TypeChat** (2023, MIT) is the same idea: put TypeScript type definitions in the prompt instead of JSON Schema, validate, repair. The academic literature treats it as a known technique — arXiv **2410.18146** ("Meaning Typed Prompting") and arXiv **2508.12475** ("Type-Driven Prompt Programming") both survey it, and the latter cites BoundaryML alongside Beurer-Kellner et al. and DSPy as parallel instances of one established practice. A prompt format is not a protectable mechanism, and this one is not even novel.
- **The only binding is commercial positioning, not legal.** The post's call to action is "migrate to BAML in less than 5 minutes." That is a funnel, not a licence term.
- **Therefore the technique costs us zero dependency.** If we want compact type-definition prompting, we write the string. No crate, no dylib, no SBOM entry, no CLA question.

**But the honest caveat the coordinator asked me to record, and I agree with it:**
- **The post states no trade-offs and no failure modes whatsoever.** For a technique post that is itself a finding.
- **It does not benchmark against native structured-output, function-calling, or constrained-decoding modes** — which is what current models expose and what a modern integration would actually use. The comparison is type-definitions vs. *hand-pasted JSON Schema in a prompt*, which is a weak baseline that most current code has already abandoned.
- **The experiment is thin and dated:** Llama2 7B, one `OrderInfo` schema, 100 runs, 6% → 0% failure. A 6/100 vs 0/100 difference on a single schema with a single old model is suggestive, not settled; and "0% on 100 runs" bounds the true rate at roughly ≤3% at 95% confidence, not at zero. Token counts (14 vs 56; "66% savings for that part of your prompt") are arithmetic and are probably right as far as they go.
- **And the surface it would apply to in ai-memory is almost nil.** Codegraph + grep across `src/` finds **no** `json_schema` / `response_format` / `tool_choice` / `function_call` usage anywhere in production code. Our prompts are already in the compact, closed-vocabulary style the post advocates: `src/llm.rs:842` `CLASSIFY_KIND_SYSTEM` ("Reply with ONLY the single lowercase kind word"), `src/llm.rs:938` `CONTRADICTION_PROMPT` ("Answer ONLY \"yes\" or \"no\""), `src/llm.rs:916` `QUERY_EXPANSION_PROMPT`, `src/llm.rs:924` `AUTO_TAG_PROMPT`. Parsing is already abstain-on-failure: `src/llm.rs:858` `parse_classified_kind` returns `Option<MemoryKind>` and the doc comment states "Returns `None` when no token names a kind — the caller then ABSTAINS (keeps the existing kind)."
- **Exactly one call site could benefit:** `src/synthesis/mod.rs:488` `SYNTHESIS_SYSTEM` — "You return strict JSON only. No markdown fences. No prose... Your only output is the JSON verdicts object specified in the developer prompt." That developer prompt is where a compact type definition would replace a schema description. It is also the highest-stakes prompt in the product (it emits `delete` verdicts), and its own doc comment at `src/synthesis/mod.rs:480` already says the envelope is "the FIRST line of defence; the K9 recheck is the LOAD-BEARING one." So even a real reliability gain there is defence-in-depth on a path that is already defended. **Worth one cheap experiment, worth zero dependency.**

### 2.7 Vote: **WATCH**

Not `REJECT` — the licence is clean, the engineering is real, the type-definition idea is free and mildly useful, and the language itself is a credible long-term answer for a *different* product than ours.
Not `PILOT` — the only part the operator actually wants to test (tracing) cannot be piloted without sending prompt inputs and completions to Boundary's hosted service, which the brief forbids and `src/egress.rs` is built to refuse.

**Re-assess triggers, any one of which flips this to PILOT:**
1. BAML ships a documented **OTLP exporter or self-hostable collector** for its tracer. This is the big one; it converts the headline claim from a SaaS funnel into a library we could measure.
2. BAML publishes a **reproducible methodology** for the 6x/200x/1000x numbers — or a third party reproduces them.
3. `baml-sys` gains **documented digest+signature verification** of the downloaded dylib, or the engine becomes buildable from source via cargo with no runtime fetch.
4. The `baml` stable crate resumes releases and the `baml_bridge` rearchitecture settles on a non-nightly version.

### 2.8 Counter-case against WATCH

The strongest argument that I am wrong:

**I am judging a product by its worst-configured default.** `default-features = false` plus `BAML_LIBRARY_PATH` turns `baml-sys` into an ordinary vendored-native-library integration, which is a solved problem that many serious projects accept — and upstream explicitly shipped a `no-download` feature *for air-gapped environments*, meaning they have already thought about our exact deployment. I have effectively let a Cargo default veto a whole project. Likewise, the tracing critique is really a critique of *Boundary's cloud*, not of BAML; nothing stops us from using the Apache-2.0 tracer with no `BOUNDARY_API_KEY` set, in which case, by their own documentation, **nothing is sent anywhere** — we would get a fast local tracer for free and the "6x faster" claim becomes testable in-process with no data leaving the host. That is a legitimate, rule-compliant pilot that I have ruled out too quickly. And on the language itself: BAML's typed-error and typed-output model maps unusually well onto our `Result`-and-abstain discipline (`ERRORS-01`, `ERRORS-09` — make illegal states unrepresentable), which is more than can be said for most agent frameworks.

**What would change my mind:** someone reading `baml-sys`'s download implementation and confirming it verifies a pinned SHA-256 before `dlopen` (the `sha2`/`hex` deps suggest it does); plus confirmation that the tracer emits locally and is measurable with no API key. If both hold, my vote should be `PILOT` — a one-week, in-process tracer benchmark against `tracing-opentelemetry`, behind `default-features = false`, with exit criterion "reproduces ≥3x in Rust on our workload, or we drop it."

---

## 3. PAW (ProgramAsWeights)

### 3.1 What it is

Compiles a natural-language spec into a small LoRA adapter (~22 MB) that runs locally on a tiny interpreter model. Paper: **"Program-as-Weights: A Programming Paradigm for Fuzzy Functions"**, Wentao Zhang, Liliana Hotsko, Woojeong Kim, Pengyu Nie, Stuart Shieber, Yuntian Deng; arXiv 2607.02512, submitted 2026-07-02, **paper licensed CC BY 4.0**. Headline result: "a 0.6B Qwen3 interpreter executing PAW programs matches the performance of direct prompting of Qwen3-32B", via "a 4B compiler trained on FuzzyBench, a 10M-example dataset."

That result, if it holds, is genuinely interesting for us — it is the shape of the posture-2 air-gapped decider.

### 3.2 Licence findings — **this is the report**

Establishing the licence of each artefact separately, as instructed:

| Artefact | Licence | Evidence |
|---|---|---|
| `github.com/programasweights/programasweights-python` (source repo) | **MIT**, "Copyright (c) 2026 ProgramAsWeights" | fetched `raw.githubusercontent.com/.../main/LICENSE` |
| All 11 repos in the GitHub org | **MIT** (10 with licences; `.github` shows none) | org repository listing |
| arXiv paper text | **CC BY 4.0** | arXiv abs page |
| `huggingface.co/programasweights/paw-4b-qwen3-0.6b` (the Standard compiler) | **NO LICENCE.** No licence field in card or YAML. `base_model: Qwen/Qwen3-4B-Instruct-2507`. | model page |
| `huggingface.co/programasweights/paw-4b-gpt2` (Compact compiler) | **NO LICENCE.** | org listing |
| `huggingface.co/programasweights/paw-programs` (**the adapters**) | **NO LICENCE. No model card at all** ("No model card"). 433+ variants. No terms of use. | model page |
| `huggingface.co/programasweights/paw-base-models` | **NO LICENCE.** Redistributes a Qwen3 GGUF (Q6_K, 623 MB) with no base-model attribution and no NOTICE. | model page |
| `.../GPT2-GGUF-Q8_0`, `.../GPT2-GGUF-Q6_K`, `.../Qwen3-0.6B-GGUF-Q6_K` | **NO LICENCE** on any of the three. | org listing |
| `huggingface.co/datasets/programasweights/paw-inference-logs` | **NO LICENCE.** Empty README. | dataset page |
| `programasweights.com` hosted API | **NO TERMS OF SERVICE, NO PRIVACY POLICY, NO ACCEPTABLE-USE POLICY located.** AGENTS.md states rate limits and `PAW_API_KEY` but **no licence statement and no data-retention or logging statement anywhere.** | AGENTS.md + site fetch + search |
| `github.com/dynamder/paw-rs` (the Rust implementation) | **MIT** — but see §3.3, it is unaffiliated | crates.io + repo |

**Seven of seven published model artefacts carry no licence.** Under the Hugging Face terms, content belongs to the uploader; absent an express grant, the default is ordinary copyright — **all rights reserved**. There is no licence to redistribute the adapters, no licence to redistribute the compiler, and arguably no licence to use them beyond what the Hub's own terms imply. For an Apache-2.0 project that publishes a CycloneDX SBOM with a `declared license` field per component (`.github/workflows/release.yml:546`), ships a `NOTICE`, and requires a CLA (`/home/fate_two/v07/v09-dev/CLA.md`), this is not a paperwork nit. It is the whole question, and the answer today is no.

**The permissive repository licence does not rescue this.** MIT on the Python SDK licenses the loader. It grants nothing over the weights the loader loads. This is precisely the trap the brief named.

**What the base models bring, and why it does not help:**
- `Qwen/Qwen3-0.6B` — **apache-2.0** (verified on the model card). Permissive, commercial use fine.
- `openai-community/gpt2` — **mit** (verified). Permissive. Its own card carries the honest caveat: *"Because large-scale language models like GPT-2 do not distinguish fact from fiction, we don't support use-cases that require the generated text to be true."* For a decider feeding a curator merge gate, that sentence should be read twice.
- `Qwen/Qwen3-4B-Instruct-2507` (the compiler's base) — Qwen3 series is Apache-2.0.

So the *bases* are clean. **That is not the problem — and it makes the omission worse, not better.** PAW had every reason to inherit Apache-2.0/MIT and simply did not label anything. Which produces a second, sharper finding:

> **`paw-base-models` and the three GGUF repos appear to redistribute Apache-2.0 Qwen3 and MIT GPT-2 derivatives with no licence file, no NOTICE, and no attribution.** Apache-2.0 §4(a)/(d) requires a redistributor to carry the licence and the NOTICE. On its face this is an upstream compliance defect in the exact artefacts we would consume. We would be taking a compliance problem into our own SBOM and inheriting somebody else's attribution failure.

**Stated plainly, as the brief requires:** *the licence of the published PAW compiler, base-model mirrors, and compiled adapters could not be determined from the sources, because none is stated anywhere.* That is a finding.

### 3.3 The Rust implementation — verified, and **the operator's premise needs correcting**

The brief said "the operator notes there is a Rust implementation; verify that rather than assuming it." Verified, and the answer is more interesting than yes or no:

**There is Rust code, but it is not theirs.** The ProgramAsWeights GitHub org has **11 repositories and zero Rust** (Python ×6, TypeScript ×2, JavaScript ×1, plus `.github`). AGENTS.md lists Python, a JS/WASM browser runtime, and a CLI — no Rust.

The Rust crates on crates.io — `paw-rs`, `paw-core`, `paw-candle`, `paw-llamacpp` — are all published by a single individual, `dynamder`, from `github.com/dynamder/paw-rs`, whose README describes itself verbatim as an **"Unofficial rust SDK for ProgramAsWeights."** Metrics:

- **2 stars, 0 forks, 0 watchers, 0 open issues, 1 owner.**
- `paw-candle` **143 total downloads**, v0.3.0, last published **2026-07-22** — no release in ~2 months, and the entire version history (0.1.0 → 0.3.0) spans four days in July.
- MIT licensed. No statement of affiliation with or endorsement by the PAW authors.

This is a bus-factor-1, four-days-of-work, unaffiliated hobby crate. `paw-candle` being candle-based is the one genuinely attractive detail — it would in principle ride the candle 0.10 stack we already carry (`candle-core`/`candle-nn`/`candle-transformers` 0.10, `tokenizers` 0.22, `hf-hub` 0.5 in `/home/fate_two/v07/v09-dev/Cargo.toml:219-231`). But putting a 143-download single-maintainer crate on the path that decides whether a memory is a contradiction, or whether the curator merges, is not a defensible supply-chain posture at any scale, let alone the ASI scale the North Star describes.

### 3.4 The hosted API — **a data-integrity and confidentiality finding**

`huggingface.co/datasets/programasweights/paw-inference-logs` is a **public** dataset of **3,773 rows**, 145 KB Parquet, containing program specifications, **user inputs**, model predictions, program IDs, model-version metadata, an "ephemeral" flag, and a **source field marking rows as API calls**. Sample tasks visible: sentiment classification, chemistry research categorisation, message urgency triage, yes/no QA.

Cross-referenced against AGENTS.md, which documents the endpoint `https://programasweights.com/api/v1/infer`, optional `PAW_API_KEY`, anonymous access at 20 compiles/hr — and **no data-retention or logging statement of any kind**, and no ToS or privacy policy I could locate anywhere on the site.

**Read together: inputs sent to the hosted PAW API have been published publicly, and there is no policy document that says they will not be.** For a product whose durable source of truth is memory *text*, that closes the remote-inference option permanently, not conditionally. It would be an unlogged, unbounded confidentiality breach dressed as a latency optimisation. Under the North Star this is a HIGH-priority finding on its own.

### 3.5 ai-memory touchpoints — where PAW would land, and what it would break

Established via codegraph at `/home/fate_two/v07/v09-dev`.

**First, a correction to the brief's starting points.** The `[decision]` provider slot of #3806 **has not landed on `release/v1.0.0` at `8b4f65a22`**. `git ls-files | grep -i decision` returns only `src/hooks/decision.rs` and `tests/pre_governance_decision_gate_2356.rs`. There is **no `src/decision.rs`, no `src/decision_config.rs`, no `src/decision_clients/`** in the tree. The slot exists as a ruling (`/ai-scratch/conductor/handoff/3806-REQUIREMENTS.md`), not as code. Any "where would it land" answer is therefore about the seams that *do* exist:

1. **`src/inference/mod.rs:85` — `trait InferenceBackend: Send + Sync`.** The real seam. `embed()`, `chat()`, and `attested_weights() -> Option<AttestedWeights>` with a `None` default. Implementors today: `CpuBackend` (`src/inference/mod.rs:116`, wrapping `embeddings::Embed` + `llm::OllamaClient`) and a `GpuBackend` stub. A PAW decider would be a third implementor. Note per `API-11`/`API-12`: the trait is deliberately dyn-compatible (`Arc<dyn InferenceBackend>`, all methods sync, no RPITIT) — a PAW backend must stay sync-callable or the seam breaks.

2. **`src/inference/mod.rs:68` `AttestedWeights` and `:263` `verify_attested_weights` — and this is where PAW structurally fails.** The record is `{ sha256: String, signature: Option<String>, label: String }`, hex SHA-256 over the weight bytes plus an optional operator Ed25519 signature; `verify_attested_weights_with_key` recomputes and refuses on mismatch — *"refusing to serve from a tampered weight file (issue #654)"* — and when a signature is present but no operator key resolves it returns *"refusing to serve (fail-CLOSED, issue #654)"*.
   **PAW's core value proposition is compile-on-demand: a 4B model generates a fresh ~22 MB LoRA from a natural-language spec in 5-10 s (or 2-5 min finetuned).** An artefact synthesised at runtime by a non-deterministic generative model **cannot be pre-pinned by an operator SHA-256, and cannot be operator-signed.** You can pin a *particular* compiled adapter, but then you have given up the thing that makes PAW PAW and you are just shipping a small fine-tune. The two designs are in direct opposition, and the conflict is on the data-integrity axis the North Star ranks highest.
   Second-order: PAW's adapter format is **bespoke** — `meta.json` specifies `lora_rank=64, lora_alpha=16, lora_num_bases=64, prefix_steps=64`, plus a `lora_mapper.pt` holding "learnable LoRA basis matrices". That is not stock PEFT LoRA. Our candle stack cannot load it without a bespoke loader, and the only reference implementations are MIT Python and an unofficial hobby crate.

3. **`src/egress.rs` — the posture gate.** `EgressClass::InferenceLlm` (`:77`), `InferenceEgressMode::{Allow, LoopbackOnly, Deny}` (`:107`), `resolve_inference_egress_mode` (`:177`) failing closed to `Deny` on an unrecognised token with the warning *"refusing to widen inference egress on a typo... (no memory content leaves the host for inference)"*, and `EgressDecision::Refuse { class, target, reason }` (`:199`) feeding the signed refusal row. PAW's remote API is unambiguously `InferenceLlm`. Given §3.4 it should never be reachable in any posture; a "150 ms remote" option that we must permanently pin to refused is an attractive nuisance in the config surface.

4. **The #3806 ruling forbids the shape of a PAW adoption.** §1, verbatim: *"the configuration must not privilege any one of them; and no provider name may be hard-coded in a control path."* The instrument is `scripts/check-vendor-literals.sh`, a CI **HARD-BLOCK** on vendor-identifier literals outside a 9-file substrate allowlist (currently `claude|openai|xai|anthropic|gemini|deepseek|groq|ollama|grok|mistral|cohere|huggingface`). §2 names the posture-2 decider as *"an NLI cross-encoder on the runtime we already ship for the reranker"* — i.e. the answer is already chosen, and it is candle, not PAW.

5. **The thing we already ship that PAW would displace.** `src/reranker.rs:366` `CROSS_ENCODER_MODEL_ID = "cross-encoder/ms-marco-MiniLM-L-6-v2"`, with `CROSS_ENCODER_FALLBACK_MODEL_SUBDIR` (`:401`), `CROSS_ENCODER_WEIGHT = 0.4` (`:253`) against `ORIGINAL_WEIGHT = 0.6`, `RERANK_POOL_MAX = 20` (`:305`), and `CrossEncoder` (`:908`) with **15 callers** across `src/handlers/recall.rs`, `src/mcp/tools/recall.rs`, `src/mcp/mod.rs`, `src/bench.rs`. Feature-gated model-pulling tests already exist (`test-with-models`, "Off by default so CI doesn't download 80MB+ on every run"). We have a working, licensed, digest-attestable local-model path. PAW would be a second one, with worse paperwork.

### 3.6 Dependency weight and exit cost

- **Via `paw-rs`/`paw-candle`:** 4 new crates from 1 unaffiliated maintainer, riding candle 0.10 which we already have — so the *crate* weight is genuinely light. The weight is entirely in trust and in the unlicensed ~22 MB-per-program artefacts, plus 594 MB (Qwen3 0.6B) or 134 MB (GPT-2) of interpreter, distributed across 6 release channels.
- **Via the Python SDK:** collides with the standing rule that **scripts are Python, production components are Rust**. A Python decider in the store/recall hot path is not a thing this product can ship.
- **Exit cost if adopted and regretted: LOW on code, HIGH on everything else.** The code is behind `InferenceBackend`, so ripping it out is a provider deletion. But a decision-provider that has been writing verdicts into memories leaves **semantic residue in the durable text** — the classified kinds, the `contradicts` edges, the curator merges it approved. Those do not un-happen when you remove the crate. That asymmetry (cheap to remove, expensive to undo) is the real exit cost, and it argues for keeping any novel decider on a reversible, evidence-logged path regardless of which one wins.

### 3.7 Vote: **REJECT** (for v1.0.0 and v1.1.0)

Four independent blockers, any one of which is sufficient:

1. **No licence on any of the seven model artefacts, or on the adapters, or on the hosted service.** We cannot put an unlicensed component in an Apache-2.0 product with a published SBOM and a CLA. This is not a risk assessment; it is a fact about what we are permitted to do.
2. **The Rust implementation is unaffiliated** — 2 stars, 143 downloads, one maintainer, self-labelled "Unofficial", dormant since July.
3. **Compile-on-demand adapters are structurally incompatible with `verify_attested_weights` (#654)** — you cannot operator-sign an artefact that a generative model will synthesise at runtime.
4. **The hosted API's user inputs are published as a public dataset, with no ToS, no privacy policy and no retention statement.**

Additionally: the #3806 ruling has already chosen the posture-2 decider, and it is a cross-encoder on the candle runtime we ship.

### 3.8 Counter-case against REJECT

The strongest argument that I am wrong:

**I have rejected a research result on paperwork.** The paper's claim — a 0.6B interpreter matching direct prompting of a 32B model — is, if true, the single most relevant result in this assessment to our hardest unsolved problem: a genuinely capable **air-gapped, zero-socket, in-process decider** for posture 2 (`/ai-scratch/conductor/handoff/3806-REQUIREMENTS.md` §2), which today is answered by an NLI cross-encoder that will abstain far more often than a real decider would. An unlicensed artefact is a *fixable* problem — one email to Yuntian Deng at the University of Waterloo, whose entire org is MIT-licensed and whose bases are Apache-2.0 and MIT, very likely produces a licence tag within a week. A missing `license: apache-2.0` line in a YAML header is a weaker reason to walk away from a 50x parameter-efficiency result than I have made it sound. And blockers 2 and 4 are avoidable by construction: we would write our own candle loader (we already have the stack, `tokenizers` and `hf-hub` in-tree) and never touch the hosted API at all. Blocker 3 is the only deep one — and even that dissolves if we use PAW as an **offline compiler** producing a small number of adapters that we then pin, sign and ship like any other weight file, accepting slower iteration in exchange for full #654 compliance. That is a coherent design I dismissed too fast.

**What would change my mind, in order:**
1. **An explicit licence (Apache-2.0 or MIT) on `paw-programs`, `paw-4b-qwen3-0.6b` and `paw-base-models`** — necessary, and close to sufficient for reopening.
2. A first-party Rust runtime, or our own candle loader for the adapter format, removing the `dynamder` dependency.
3. A published ToS and retention policy for the hosted API, plus removal or explicit consent-gating of `paw-inference-logs` — needed only if we ever wanted the remote path, which on current evidence we should not.
4. Independent reproduction of the 0.6B-matches-32B claim on a decision-shaped task (typed verdict over a closed vocabulary), not a generation benchmark.

If (1) and (2) land, my vote becomes **PILOT**: offline-compiled, digest-pinned, operator-signed adapters behind `InferenceBackend`, measured head-to-head against the cross-encoder on abstain rate and false-`contradicts` rate, with exit criterion "fewer abstentions at equal or lower false-positive rate, or we keep the cross-encoder."

---

## 4. Cross-cutting supply-chain observation (not a vote)

Both subjects surfaced the same gap on our side, and it is worth a line to the Conductor independent of either verdict.

**There is no `deny.toml` and no `cargo-deny` licence gate in this repository.** `ls deny.toml THIRD-PARTY-NOTICES*` returns nothing; the only licence-related CI reference is the CycloneDX SBOM in `.github/workflows/release.yml`, whose own comment is admirably candid: *"This is an inventory, not an assurance — it lists what is in the dependency graph and vouches for none of it."*

`rust-1.98` **[TOOL-04] (P1)** is explicit that the supply-chain lockdown is `rust-version` + `resolver = "3"` + committed `Cargo.lock` + *"gate `cargo audit`/`cargo deny` in CI"*, because `cargo deny` *"fail[s] the build on a known-vulnerable, yanked, or **disallowed-license** dependency before it ships."* We have `cargo audit` (RustSec) as the vulnerability gate and a committed `Cargo.lock`; we do not have the licence half. Today that costs nothing because our tree is conventional. The moment anyone evaluates a dependency like either of these two, the absence means the judgement is made by a human reading a web page — which is exactly what this assessment is, and exactly what should not be the control.

**Suggested follow-up issue (not filed by me — read-only):** add `deny.toml` with an allow-list (`Apache-2.0`, `MIT`, `BSD-*`, `ISC`, `Unicode-*`, `CC0-1.0` — the last already in use for `notify` per the `fs-notify` feature comment) and gate `cargo deny check licenses` in CI. This is a small change that would have answered the BAML half of this assessment mechanically, and would have hard-blocked PAW's unlicensed artefacts at the door.

---

## 5. Method notes and limits

- Nothing was installed, downloaded, vendored or executed. No project data, memory content or credential was sent anywhere.
- Code claims were established with the codegraph CLI at `/home/fate_two/v07/v09-dev` (the MCP server failed to connect this session; the CLI at `/home/fate_two/.local/bin/codegraph` was used against the pinned release-dev index), confirmed with targeted grep where codegraph did not surface a literal.
- **Explicitly not established:** the per-file licences under `engine/vendored/` in BAML; whether `baml-sys` digest-verifies its downloaded dylib (deps suggest yes, docs say nothing, source unread); Boundary Studio's terms and pricing; the existence of any PAW terms of service.
- **Correction offered to the brief:** no 64 KiB cap exists on the `/metrics` renderer at `8b4f65a22` (`src/metrics.rs:1418`); and the #3806 `[decision]` files named as starting points are not in the tree at this commit.
- **Correction offered to the operator:** a PAW Rust implementation exists but is **not first-party** — `github.com/dynamder/paw-rs`, self-described "Unofficial", 2 stars.

---

## 6. Addendum — two further BAML sources (release notes 0.19.0; team page)

Folded in after the main assessment at the coordinator's direction. **Both reinforce `WATCH`; neither moves me to `REJECT` or `PILOT`.**

### 6.1 API stability — quantified, and it is worse than "pre-1.0 in version number only"

Breaking changes I could enumerate from the release notes themselves:

| Release | Date | Breaking changes | Character |
|---|---|---|---|
| **0.19.0** | 2026-09-11 | **11** | Function spec/streaming redesign (`Fn@spec()` / `Fn@stream()`); **"over 30 type renames"** in the standard library (`ai.ClientSelector`→`ai.Selector`, `anthropic.AnthropicClient`→`anthropic.Client`, …); error-type changes (`baml.sap.parse` now throws `ParseError` not `LlmClient`); panic-type change (`AssertionFailed` not `UserPanic`); comparison API overhaul (`baml.ops.Compare` now requires `cmp(self, other) -> baml.ops.Ordering throws never`); union member access narrowed; `unreflect` restricted to a local type statement; `baml.future.all_complete` **removed**; agent-journal content restructured (`UserMessage.content` / `ToolCompleted.content` are now `ai.content.Block[]`); `baml.ws.WsStream`→`baml.ws.WebSocket` with a changed `send` signature; changelog-feed endpoints removed. |
| **0.18.0** | 2026-08-27 | **8** | `ai.Runner` interface still changing; reflection consolidated into `reflect.*`; `baml.json.encode` **deleted**; **Jinja template support dropped** entirely; v0 test blocks removed; `ctx.output_format` became `ctx.output_format()`; SDK output directory moved; C# client renamed `baml_client`→`baml_sdk`. |
| **0.17.0** | 2026-08-14 | not enumerated (not fetched) | — |

**~19 breaking changes across two releases shipped 15 days apart**, on a roughly two-week cadence. Note what is in that list: not deprecations with shims, but *deletions* (`baml.json.encode`, `all_complete`), *whole-subsystem removals* (Jinja templating), *exception-type changes* (which silently break `catch` clauses rather than failing at compile time in the dynamic SDKs), and a 30+ item rename sweep.

**Migration burden for a consumer, concretely:** every minor bump is a scheduled refactor of every call site, not a `cargo update`. At two weeks per minor, a consumer either (a) pins and falls behind — on a project whose stable Rust crate is already 5 months stale (§2.4) — or (b) budgets recurring migration work indefinitely. For a GA product on an LTS-shaped release train with enterprise and government customers, (b) is not schedulable and (a) means running unmaintained.

Read against `rust-1.98` **[API-07]** (`#[non_exhaustive]` on types expected to grow) and **[API-03]** (seal traits so methods can be added non-breakingly): these are exactly the disciplines that let a library evolve *without* a rename sweep, and BAML is visibly not practising the equivalent. That is a choice a pre-1.0 language is entitled to make. It is not a choice a dependency in our decision path can make for us.

**The only number in 0.19.0 is not a performance number.** Verbatim: *"Displayed O2 bytecode instructions: Baseline 99,860 → Optimized 93,984, Reduction 5,876 (5.9%)"*, and to their credit the notes themselves frame it as *"a static instruction-count result, not a throughput or end-to-end latency benchmark"* covering only *"the pre-existing bytecode snapshot inventory."* Honest framing, but it is not evidence of speed.

### 6.2 The tracing claim is **UNSUBSTANTIATED** — stated plainly, as asked

I could source the 6x/200x/1000x claim to **exactly one place: the boundaryml.com home page.** It is absent from:
- the GitHub README,
- release notes **0.19.0** (2026-09-11) — no tracing, no observability, no OpenTelemetry content at all,
- release notes **0.18.0** (2026-08-27) — same,
- any published methodology, benchmark harness, or dataset I could locate.

**I found no artefact that substantiates it and no way to reproduce it from public sources.** Per the brief's distinction: this is a **vendor claim**, not a measurement, and it should be written down as unsubstantiated wherever it is repeated — including in the framing that prompted this assessment. The one *verified* fact adjacent to it is structural, not numerical: the documented sink for those traces is Boundary's hosted Studio, gated on `BOUNDARY_API_KEY`, with no OTLP export (§2.5).

### 6.3 Open core confirmed — **the useful half is the unpriced hosted product**

The coordinator's question was whether Apache-2.0 covers the whole product or only the open core. Answered from Boundary's own pricing page, verbatim:

- *"BAML is free and open source."*
- *"Cloud pricing has not yet been published on this page."*
- BAML Cloud will provide **"Observability, team controls, governance."**
- *"Cloud is not required to run BAML locally."*

**So observability — the operator's entire reason for looking at BAML — is named on the vendor's own pricing page as the forthcoming paid Cloud product.** This is a textbook open-core split, and it has been the plan since the beginning: their launch post is titled *"Announcing BAML — The typesafe interface to LLMs, with built-in testing, guardrails and observability."* Observability was in the pitch on day one and is now the monetisation surface.

Practical consequence: the Apache-2.0 finding in §2.2 is **real but partial**. It covers the compiler, runtime, VM, generators and the client-side tracer. It does not and cannot cover the collector, the dashboard, retention, or the governance features — those are a service under terms that **do not exist publicly yet** (§2.2: no ToS located, no pricing). Adopting BAML for tracing means signing an unwritten contract later.

**Mitigating, and worth stating fairly:** there is **no CLA and no DCO** in `CONTRIBUTING.md` — contributors retain copyright and have granted only Apache-2.0. That makes a wholesale relicence of the existing codebase legally awkward (Boundary would need permission from every outside contributor for code it does not own), and Apache-2.0 grants on already-published versions are **irrevocable**, including its §3 patent grant. So the fork escape hatch is genuine: a BSL-style rug-pull could only apply to *future* code. That is a real, if cold, comfort — a fork of a 26-sub-crate Rust compiler and VM is not a thing this team would take on.

### 6.4 Vendor viability and bus factor

From the team page: **9 people visible** — Vaibhav Gupta (co-founder/CEO; previously Google Pixel 4 depth + face unlock, Microsoft HoloLens), Aaron Villalpando (co-founder/CTO; seven years at Amazon, EC2 monitoring and livestreaming), and ~7 engineers (Sam Lijin, Antonio Sarosi, Paulo Rossi, Kai Orita, Avery Townsend, Dhilan Shah, one unlabelled). Backgrounds at Google, Amazon, Y Combinator. Tagline: *"Basically a made up language."* The page cites **8,423** GitHub stars; the repo currently shows **9.2k** — the page is stale, which is a small signal about how closely the marketing surface tracks reality, and a reminder that the home-page tracing claim may be equally unrefreshed.

**Disclosed: nothing.** No funding, no investors, no incorporation detail, no revenue model, no pricing, no licensing terms. Read against a founder blog post titled *"1 co-founder, 5 years, 12 pivots, still not dead"* (2025-12-30), the shape is clear: a venture-track, pre-revenue, nine-person company that has pivoted repeatedly and whose monetisation (Cloud) is announced but unpriced.

**Bus factor, concretely:**
- **Crate ownership is two people** — `hellovai` and `2kai2kai2` (§2.2). Two humans can publish to the crates.io namespace we would depend on.
- **Engineering bus factor ~7**, all in one company, on one funding runway, with no disclosed revenue.
- **A 26-sub-crate Rust compiler + bytecode VM + LSP + WASM target is far beyond community-rescue scale.** If the company stops, the code survives under Apache-2.0 but effectively nobody picks it up. Compare our actual fallback (`src/reranker.rs`, a cross-encoder on candle): if candle stops, the model file and the maths remain, and the replacement cost is bounded.

**What happens to us in each scenario:**
| Scenario | Effect on ai-memory |
|---|---|
| Pivot to paid control plane (**most likely** — it is the stated plan) | Local BAML keeps working; the tracing capability we came for becomes a paid SaaS with data egress. We lose nothing we had, and gain nothing we wanted. |
| Acquisition | New owner controls the crates.io namespace, the GitHub releases feed **that `baml-sys` auto-downloads dylibs from by default** (§2.3), and the Cloud terms. The dylib-fetch default becomes an acquirer-controlled code-delivery channel into our runtime. This is the scenario where §2.3 stops being a hygiene issue and becomes a genuine risk. |
| Shutdown | Apache-2.0 code survives and is forkable; the GitHub releases dylib feed does not survive, so **the default acquisition path breaks** and any consumer relying on it is stranded until they vendor the library themselves. |

**None of these is catastrophic *if* the dependency sits behind `InferenceBackend` (`src/inference/mod.rs:85`) and the dylib auto-download is off.** That remains the mitigation, and it remains the reason the vote is `WATCH` and not `REJECT`.

### 6.5 One open item the Conductor should chase — a possible direct collision with the #3806 ruling

The BAML blog index lists a post dated **2026-09-17** titled **"TypeSafe AI's Jev model is coming to BAML v1."** I could not retrieve its content — the slug I tried returned "Post Not Found" and it is not yet search-indexed — so **I am reporting this as a listing-level fact with the content unverified, not as an established finding.**

It matters because our binding ruling of **2026-09-19** (`/ai-scratch/conductor/handoff/3806-REQUIREMENTS.md` §1), issued two days later, says of the same model, verbatim: *"TypeSafe Jev 1.13 is **one instance of a model class**, and the product must never encode it as the requirement... the configuration must not privilege any one of them; and no provider name may be hard-coded in a control path."*

If BAML v1 is binding a named vendor model into the language or runtime, then BAML's v1 direction runs **directly counter** to the architectural principle we just ruled on, and against the gate that enforces it (`scripts/check-vendor-literals.sh`, a CI hard-block on vendor literals outside a 9-file allowlist). **This should be verified before any BAML re-assessment**, and it is a sharper re-assessment trigger than the four in §2.7 — add it as trigger 5: *does BAML v1 privilege a named vendor model?* If yes, `WATCH` should harden toward `REJECT` on architectural grounds independent of licensing.

### 6.6 Net effect on the vote

**`WATCH` stands, with increased confidence.** The new evidence strengthens the cost side on three axes — API instability (~19 breaking changes in 15 days), confirmed open-core with observability as the unpriced paid product, and a nine-person pre-revenue vendor with a two-person crate namespace — while the benefit side is now formally **unsubstantiated** rather than merely unreproduced. The one thing genuinely worth taking from BAML remains **free**: type-definition prompting (§2.6), which needs no dependency, no licence, no account, and no migration budget.

### 6.7 Note on the codegraph correction

Acknowledged, and it makes no difference to the findings: `/home/fate_two/v07/v09-dev` and `/mnt/t9/v07/v09-dev` are **the same directory** — `readlink -f` resolves the former to the latter and `stat` confirms an identical device:inode pair (`2049:73675137`) for `Cargo.toml` on both paths. Every codegraph result in this report was produced by the shell CLI (`/home/fate_two/.local/bin/codegraph`) against that one tree at `8b4f65a22`. The MCP transport was not used and nothing was blocked by its absence.
