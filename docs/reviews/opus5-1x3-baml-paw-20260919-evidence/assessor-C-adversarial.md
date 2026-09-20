# Independent assessment — BAML and PAW (ProgramAsWeights)

**Assessor C (adversarial brief). ai:opus-5. 2026-09-19.**
Written without reading assessors A or B. Read-only: nothing installed, no dependency added, no weights
downloaded, no vendor code executed, no project data sent anywhere.

---

## 1. Votes

| Project | Vote | One-line reason |
|---|---|---|
| **BAML** (boundaryml.com / BoundaryML/baml) | **REJECT** for v1.0.0 and v1.1.0 | The headline claim is unsourced and, even if true, measures a baseline we do not run; the Rust production path fetches and `dlopen`s an unverified native binary; the capability of interest is the paid hosted tier of a pre-1.0 language that renamed its standard library nine days ago. |
| **PAW** (ProgramAsWeights) | **REJECT** for v1.0.0 and v1.1.0 | Every weight artefact we would depend on carries **no declared licence** (verified); compilation is hosted, so a spec is off-host data; the artefact is free-text-out with no logprobs and therefore structurally cannot satisfy our confidence rule; and the paper's own table shows it losing to a 32B local model on all four external benchmarks. |

Both are **features**. We are in a GA freeze that admits defects plus exactly one operator-admitted feature
(#3806). Neither belongs near v1.0.0. Detail in §5.

The strongest case *for* each is in §3.7 and §4.7 — I was hunting for reasons to reject and I still found real
value in one component of each. Neither piece of value requires taking the dependency.

---

## 2. Method, and what I could not establish

Sources fetched directly: boundaryml.com (`/index.md`, `/pricing.md`, `/quickstart.md`, sitemap, embedded
JSON-LD), docs.boundaryml.com `llms.txt`, the BAML GitHub repo (tree, `LICENSE`, `TELEMETRY.md`,
`languages/rust/baml-sys/src/download.rs`, `baml_language/sdks/rust/bridge_rust/src/loader/download.rs`,
`baml_language/crates/baml_tests/BENCHMARKS.md`, `benches/profiling_overhead.rs`,
`typescript2/app-website/app/what-is-baml/page.tsx`), crates.io API for `baml` / `baml-sys` / `baml_bridge` /
`paw-core` / `paw-candle` / `paw-rs`, the GitHub API for both orgs, the Hugging Face API for every
`programasweights` model and dataset, and the arXiv PDF 2607.02512 extracted locally with `pdftotext` (1,587
lines, read in full at the results, appendix and limitations sections). ai-memory anchored with the
`codegraph` CLI at `/home/fate_two/v07/v09-dev` plus direct reads (the codegraph **MCP** server failed to
connect this session; the **CLI** worked and is what I used — codegraph was available and was used).

**Could not establish (stated as findings, not assumptions):**

- **No methodology exists in public for the BAML tracing claim.** Not in the README, not in
  `docs.boundaryml.com` (its `llms.txt` index has no tracing or observability page outside Boundary Studio),
  not in `pricing.md`, not in the site's own agent-facing `index.md` mirror, not in the 0.19.0 release notes,
  and not in the repo. See §3.2.
- **No licence is declared on any PAW model or dataset artefact.** Verified mechanically, not by eyeballing a
  page. See §4.1.
- Whether the public HF dataset `programasweights/paw-inference-logs` (records tagged `source: "api"`)
  contains third-party users' hosted-API traffic or only the vendor's own evaluation runs. The dataset card is
  empty. This is unresolved and it is the kind of thing that must be resolved *before* an experiment, not after.
- BAML's funding. Aggregators returned two mutually contradictory figures in a single response ($500k
  convertible notes; $48.5M across five rounds). I treat both as unverified. What *is* verified is in §3.5.

---

# 3. BAML

## 3.1 What it is, and the licence facts

Apache-2.0, verified two ways: `repos/BoundaryML/baml` reports `license.spdx_id = Apache-2.0`, and the
`LICENSE` file at `canary` is the Apache 2.0 text. `language = Rust`, 9,200 stars, pushed today.

The Rust crates are Apache-2.0 too — but read the publication dates, because they are the story:

| crate | version | published | what it is |
|---|---|---|---|
| `baml` | 0.221.0 | **2026-04-15** | "BAML runtime for Rust" — the *legacy* (v0) engine binding |
| `baml-sys` | 0.221.0 | **2026-04-15** | "BAML FFI bindings with **runtime dynamic library loading**" |
| `baml_bridge` | 0.20.1-**nightly**.20260918.a | 2026-09-19 | the *new* language's Rust bridge — **pre-release only** |

The stable Rust crate is five months stale against a repo that pushes daily. The new language's Rust bridge
exists only as a nightly. There is, today, **no stable pure-Rust way to consume the BAML that has the
observability story**.

`TELEMETRY.md`: the CLI collects anonymous usage telemetry **by default**, opt-out. It excludes prompts,
source, secrets and file paths (I read the list). That is a reasonable policy for a dev tool and a live
question for a build environment under a zero-deviation egress posture.

## 3.2 The tracing claim — attacked

**The verbatim claim, and where it actually lives.** It is not on any machine-readable surface. I found it in
the repository, in the source of the marketing page:

`typescript2/app-website/app/what-is-baml/page.tsx:195`
> `body: 'Agents write more code than any human can read. Telemetry is the only way to understand what happened. BAML traces every function instead of sampling a percentage. It's 6x faster than OpenTelemetry in Rust, 200x faster in Python, and the traces 1000x smaller.'`

Two lines below it, `readMore: 'How BAML keeps tracing fast enough to always leave on'` — and at
`page.tsx:809` that "Read more" resolves to `href="/techdocs"`, a generic docs landing page. **There is no
deep-dive behind the claim.** The claim is a string in a `SECTIONS` array with a dangling promise of detail.

**What is being compared is never stated.** The claim names no workload, no hardware, no span rate, no
attribute cardinality, no exporter, no OpenTelemetry SDK version, no sampler, and no batching configuration.
Each of those changes the answer by an order of magnitude on its own. A head sampler at 1% and a full-fidelity
tail sampler with an OTLP/gRPC batch exporter are not the same baseline, and the claim distinguishes neither.

**The repository contains no OpenTelemetry comparison.** GitHub code search for `opentelemetry` in
`BoundaryML/baml` returns six files: a vendored minijinja README, the marketing page above, a playground
React component, a Go `go.mod`, and two lockfiles. Zero benchmark code. The benchmark harness that *does*
exist is `baml_language/crates/baml_tests/benches/profiling_overhead.rs`, and its own header says what it
measures:

> "Overhead ratio = this target's median ÷ the same workload's median in `runtime_benchmark`."

That is BAML's profiler **on versus off**, in BAML, on BAML's corpus. It is a self-overhead ratio. It is not
an OpenTelemetry comparison and it cannot produce a "6x faster than OpenTelemetry" number.

**The vendor's own explanation of the mechanism yields 8x, not 1000x.** On their 2026-07-07 "agent
observability" episode the stated mechanism for trace size is that OTel's attribute model forces flattening:
"OTel forces you to flatten everything into strings", and "Turning 100 bytes of real data into a JSON string
can balloon it to 800 bytes over the wire." 100 → 800 bytes is **8x**. The headline says **1000x**. Two orders
of magnitude separate the marketing number from the vendor's own account of where it comes from. That is not
a rounding disagreement; it means the 1000x is measuring something other than the mechanism they describe.

**"1000x smaller" and "every function instead of sampling" partially cancel, and the claim hides the free
parameter.** Total volume = per-trace size × trace count. If the OTel baseline head-samples at 1% (a common
production default) and BAML records 100%, BAML emits 100x more traces. 1000x smaller each × 100x more = **10x
smaller in total**, not 1000x. At 0.1% sampling the two halves cancel exactly and the net is **break-even**.
At 100% OTel sampling the 1000x survives — but then the speed comparison is against a configuration almost
nobody runs in production, which is the opposite of a fair baseline. The claim never states the sampling rate,
and the sampling rate is the single number that decides whether the claim means anything. A statement whose
truth value is entirely controlled by an unstated parameter is not a measurement.

**A tracer that is faster because it records less is not faster at the same job.** I cannot falsify the
numbers — no harness is published — but I can say what shape they have. "1000x smaller" is exactly the
signature of recording a different, smaller thing: BAML records typed values into its own binary event format
(`bex_events`, `trace_value_encode.rs`, `trace_heap.rs`) inside its own VM, where it controls the type system
and can encode a value by reference into an interned heap. OTel records a vendor-neutral, cross-process,
cross-language wire format with W3C context propagation, resource attributes, and semantic conventions, so
that a span from a Rust service joins a span from a Python service in someone else's backend. Those are not
the same job. BAML's format cannot leave the BAML VM. **Judgement: the claim is plausible as an
apples-to-oranges artefact of scope, unsourced as a measurement, and marketing until proven.**

**And it does not apply to us at all.** We do not run OpenTelemetry. `Cargo.toml:66-72` is the whole
observability dependency set: `tracing = "0.1"`, `tracing-subscriber` (`env-filter`, `fmt`, `json`),
`tracing-appender = "0.2"`. There is no `opentelemetry` crate, no `tracing-opentelemetry`, no OTLP exporter
anywhere in `src/`. `src/logging.rs:11-13` states the posture: *"Default-OFF. Without a `[logging]` block in
`config.toml` the daemon keeps the legacy `tracing-subscriber::fmt` setup that writes to stderr."* Our 1,618
`tracing::` call sites compile to a level check against a static max-level filter; a disabled call site costs
single-digit nanoseconds. **The baseline BAML beats by 6x is one we have never had, and the baseline we
actually run is already close to free.** Adopting a programming language to win a benchmark against a library
we do not use is not an optimisation, it is a rewrite with a benchmark attached.

## 3.3 The type-definition prompting claim — attacked (and this is the one that partly survives)

Source: `boundaryml.com/blog/type-definition-prompting-baml`, Aaron Villalpando, **"over 2 years ago"** —
i.e. roughly mid-2024.

**The statistics are nominally significant and practically fragile.** 6/100 versus 0/100, one task, one model.
I computed it rather than asserting it: Fisher's exact two-sided **p = 0.029**; one-sided p = 0.014. Wilson 95%
CIs: 6/100 = **[2.8%, 12.5%]**, 0/100 = **[0%, 3.7%]** (rule of three: true rate could be up to 3%). So the
intervals **overlap** in [2.8%, 3.7%]. The honest reading is: the effect is real at the 5% level on this one
run, the true improvement could be as small as ~2.3 points, and it rests on a single task with a single model
and **no stated temperature, no stated seeds, no published prompts, no released benchmark code, and no
repetition across tasks**. It is a suggestive demo, not a measurement you would bet a decision seam on. It is
also, per the post's own definition, a **format**-compliance measurement — failures are "the LLM output
incorrect JSON structure (e.g. returning schema metadata instead of actual values)" — not an accuracy
measurement. Nothing in it says the extracted values were more *correct*.

**The baseline is a configuration we would never run.** The comparison is JSON Schema **in the prompt**, via
the Instructor library, on **Llama2 7B**. That is a 2024 artefact. It predates mainstream native structured
output and constrained decoding. Our decision plane does the opposite by design. From
`origin/f1/3806-w1abc`, commit `271279072`:

> "`chat::OpenAiCompatibleDecider` sends a STRUCTURED chat-completions request — `response_format` json_schema
> (strict, the closed vocabulary as an `enum`), `logprobs`, `temperature = 0` and a fixed `seed`."

With `strict` json_schema the provider constrains decoding to the grammar. The failure mode the post measures
— the model echoing schema metadata instead of filling it — **cannot occur**, because the grammar does not
admit it. A 6-point format-compliance win against an unconstrained prompt is a win against a problem we have
already made unrepresentable. This is the sharpest form of "benchmark against a configuration nobody uses".

**The post states no trade-offs, and there are real ones.** A compact type definition is lossy exactly where
an auditor needs precision. JSON Schema expresses, and a `verb: "add|update|delete|no_op"` string does not:
numeric bounds (`minimum`/`maximum`/`multipleOf`), string constraints (`pattern`, `format`, `minLength`),
array constraints (`minItems`, `uniqueItems`), required-versus-optional as a first-class set rather than a
comment, discriminated unions with `oneOf` + `discriminator`, and conditional requirements (`if`/`then`,
`dependentRequired` — "`merged_content` is required **iff** `verb == "update"`", which is precisely our
synthesis contract, `src/synthesis/mod.rs:177-181`). Crucially, a JSON Schema is *machine-checkable*: it can
be handed to the provider as a grammar, validated server-side, and diffed in review. A prose type sketch can
only be checked by the model's goodwill. For a seam that deletes memories, "the model usually formats it
right" is a weaker guarantee than "the decoder could not have emitted anything else."

**The interaction with our confidence rule — the question the coordinator asked, and the answer matters.**
Yes, it changes the logprob structure, and in the direction that *helps* us, but only under constrained
decoding. `src/decision.rs` (W1a) requires confidence to be *attributed*: per commit `271279072`, confidence is
emitted "only when exactly one contiguous run of returned logprob tokens reconstructs the decided label
exactly, as `exp(sum logprob)` over that run." With a strict json_schema `enum`, the label tokens are
constrained to the closed vocabulary, so the logprob mass over that run is a true posterior over the permitted
labels and the attribution is unambiguous. With a *loose* type-definition prompt and free decoding, the model
may emit `"delete"`, ` delete`, `"Delete"`, or a preamble — and the token run that reconstructs the label
becomes ambiguous or straddling, which by our own rule DEGRADES to no confidence. **So the honest finding is
the inverse of the coordinator's worry: the risk is not that type-definition prompting quietly degrades our
calibration evidence — it is that adopting it *instead of* strict json_schema would destroy the calibration
evidence outright, by removing the grammar that makes the label run attributable.** Type-definition prompting
plus constrained decoding is fine. Type-definition prompting *as a replacement for* constrained decoding would
silently convert a large fraction of our decisions into "no confidence", and a `confidence < threshold` guard
on a destructive seam would then fall through to abstain far more often than it should. That is a real trap
and it is worth writing down even though we are not going to walk into it.

**Separability — and we have already done it.** The technique is one string literal. And we already use it, at
the only seam where it applies. `src/synthesis/mod.rs:267-270`:

```
Output JSON shape (NO PROSE, NO MARKDOWN FENCE):
{"verdicts":[{"candidate_id":"<id>","verb":"add|update|delete|no_op","merged_content":"<only when verb=update>","reason":"<short string>"}]}
```

That is type-definition prompting: a compact inline shape, a literal union for the closed vocabulary, a
conditional field annotated in place. Not a JSON Schema. Roughly 60 tokens where the equivalent JSON Schema
would be 200+. The blog's 60–66% token saving is a saving **we already banked**, at our only prompt-level
structured-output seam, some time before the post was written. The remaining prompt-level seams behave the
same way: `classify_kind` (`src/llm.rs:2131-2141`) selects over a closed set from a prompt, and
`detect_contradiction_async` (`src/llm.rs:2900`) asks a boolean.

**Verdict on the technique, separately from the product: the idea is sound and already implemented. The post
is evidence for a technique; the project presents it as evidence for a product** — it ends
*"If you'd like to try out type-definition prompting, we have incorporated it into our DSL — called BAML."*
That is the conflation, stated in their own last line. There is nothing here to adopt. There is nothing here
to change either.

## 3.4 Stability — the cost of tracking it

BAML ships two version lines simultaneously: the legacy engine at `v0.226.x` and the new language at
`baml-language-0.20.0`, released **2026-09-18** with nightlies cut daily (`0.20.1-nightly.20260918.a`
published 2026-09-19 08:24Z).

The 0.19.0 release notes — nine days before 0.20.0 — carry **eleven breaking changes**, including renames
across the standard library (`ai.ClientSelector` → `ai.Selector`, `anthropic.AnthropicClient` →
`anthropic.Client`), a redesigned function/streaming API (`Fn@spec()` / `Fn@stream()`, `override_client` →
`client`), a rebuilt comparison API (`baml.ops.Compare.compare` → `cmp` with `baml.ops.Ordering throws never`,
`baml.Comparable` removed), changed error and panic types (`baml.errors.ParseError`,
`baml.panics.AssertionFailed`), semantic changes to union member access and `unreflect`, `all_complete` →
`all_settled`, the agent journal moving from string content to `ai.content.Block[]`, and
`baml.ws.WsStream` → `baml.ws.WebSocket` with a changed `close` signature. The only figure in the post is a
**static bytecode inventory count** — 99,860 → 93,984 displayed O2 instructions, "5,876 (5.9%)" — explicitly
covering "the pre-existing bytecode snapshot inventory, including test and standard-library scaffolding".
That is a code-size delta over a snapshot corpus. It is not a throughput benchmark and should not be read as
one. No tracing content. No OpenTelemetry comparison. No licensing statement.

**And the new abstraction leaks in the release notes themselves.** The structured content model that replaced
string journals immediately requires provider-conditional knowledge:

> "Gemini/Vertex accepts all four media kinds in user turns and tool results. Anthropic accepts images and
> PDFs. OpenAI Responses accepts user images, audio, and PDFs; tool audio is moved to a following user turn."

So we would pay the full cost of adopting a vendor abstraction over providers **and still write
provider-conditional code**. That is the worst of both: the coupling without the insulation. Our `[decision]`
slot solves the same problem by refusing to abstract it — `src/decision_config.rs` and the W1c ruling state
each endpoint's actual capability honestly ("Ollama via `/v1/chat/completions` accepted — the native route has
neither json_schema nor logprobs; state it in the docs so an operator does not expect `/api/chat`"). Naming
the difference beats papering over it.

Against our own engineering discipline — `tests/qual_10_module_size_ceiling.rs` requires a *measured* ceiling
with a dated rationale for every module growth, and a ceiling "carried across a rebase is UNVERIFIED until
re-measured" — tracking a daily-nightly pre-1.0 language that renames its standard library on a nine-day
cadence is not a dependency, it is a subscription to rework.

## 3.5 Supply chain, vendor, and the thing that actually disqualifies it

**The Rust path fetches and executes an unverified native binary.** `baml-sys` is not a normal `-sys` crate.
Its own README:

> "Unlike traditional `-sys` crates that link at compile time, `baml-sys` loads the library dynamically at
> runtime using `libloading`." Resolution order ends in "**Auto-download** — From GitHub releases".

`languages/rust/baml-sys/src/download.rs` fetches `https://github.com/{repo}/releases/download/{version}/{filename}`
over `ureq`, then:

```rust
let expected_checksum = download_checksum(&checksum_url, filename).ok();
...
// Verify checksum if available
if let Some(expected) = expected_checksum { ... }
```

If the `.sha256` sidecar 404s, times out, or omits the filename line, `expected_checksum` is `None`, the
verification block is skipped entirely, the artefact is renamed into `~/.cache/baml/libs/{VERSION}/`,
`chmod 0755`'d, and `dlopen`'d. The new bridge does the same thing and says so in its doc comment
(`baml_language/sdks/rust/bridge_rust/src/loader/download.rs:3-8`):

> "fetch the `.sha256` sidecar first (**a missing sidecar is a warning, not a failure** — the artifact and its
> checksum come from the same origin either way)"

That parenthetical is a fail-**open** integrity check on native code execution, with the justification stated
out loud. Against `3824-final` — *"Only encrypted data in transit is allowed within the ai-memory ecosystem,
regardless of network or system boundary… No opt-in plaintext. No operator override… Any new network client,
listener, socket or pipe is encrypted from its first commit… **One predicate** decides whether a target is
permissible, in `src/egress.rs`, consulted by every client"* — this dependency introduces an HTTP client we do
not control, that does not consult `evaluate_inference_egress` (`src/egress.rs:279`), that does not fail
closed, and that puts a downloaded `.so` into our address space. In an air-gapped install (posture 2 of
`3806-REQUIREMENTS.md`) it simply cannot resolve its own runtime. **This alone disqualifies the Rust
production path as shipped, independent of every benchmark question.**

**The capability of interest is the paid tier.** `boundaryml.com/pricing.md`:

> "BAML Cloud is coming later this year, adding hosted capabilities for: **Observability**, Team controls,
> Governance. … Cloud pricing has not yet been published on this page."

Observability is bullet one. The marketing page's section 1 is "Observability and profiling" with tabs
"Always-on Observability / Data Enrichment / Agents Using Traces / Runs at Scale". This is an open-core
structure in which **the exact capability whose benchmark drew our attention is the one slated for the
unpriced hosted tier**. Betting a production observability posture on a free tier of an unpriced, unshipped
commercial product is the classic version of this mistake.

**Entity and bus factor.** The site's own embedded JSON-LD declares
`"@type":"Organization","legalName":"Gloo Chat, Inc.","name":"BAML"` — the legal entity is not "Boundary ML".
Y Combinator-backed; founded 2023; public team ~9 people, ~7 engineers; founders Vaibhav Gupta (CEO) and
Aaron Villalpando (CTO). Funding figures from aggregators were mutually contradictory in a single query
($500k convertible notes vs $48.5M/5 rounds) and I treat both as unverified. What is verified is enough: a
company of roughly seven engineers is building, simultaneously, a Turing-complete programming language, a
bytecode VM, a profiler, SDKs for six host languages, an LSP, a VSCode/JetBrains/Zed extension family, and an
unshipped cloud product — while renaming its standard library. The Apache-2.0 licence protects the code we
have; it does not protect the *maintenance*. If the cloud pivot takes the team's attention, the open core does
not stop being open, it stops being current — and the stale-since-April `baml` 0.221.0 crate is what that
already looks like.

**Does it phone home?** Honest answer, three parts: (a) the language runtime does not —
`pricing.md`: "BAML runs on your machine and does not call Boundary's servers"; (b) the CLI does, anonymously
and opt-out by default (`TELEMETRY.md`, excluding prompts/source/paths/secrets); (c) the **Rust binding does**,
to GitHub releases, for a native library, at first use, with optional integrity verification.

## 3.6 Where BAML would land in our code — concretely

| Our seam (file:symbol) | What BAML would replace | Verdict |
|---|---|---|
| `src/synthesis/mod.rs:218` `build_prompt_with_cap`, `:267-270` output-shape literal, `:488` `SYNTHESIS_SYSTEM` | the prompt + its inline type definition | Already type-definition-shaped. Zero delta. |
| `src/synthesis/mod.rs:315` `extract_json_object`, `:363-390` `parse_and_validate` | hand-rolled balanced-brace JSON recovery + verdict validation | **The one place BAML has something we don't** — see §3.7. |
| `src/llm.rs:2131` `classify_kind`, `:2887`/`:2900` `detect_contradiction[_async]` | prompt + parse for the closed-vocabulary seams | Being replaced by `[decision]` with strict json_schema + logprobs, which is strictly stronger than prompt-level typing. |
| `src/decision.rs` (`origin/f1/3806-w1abc`) `DecisionProvider`, `DecisionSource`, `AbstainReason`, `Confidence` | the typed-decision contract | BAML has no analogue of attributed confidence or first-class abstain. It would be a downgrade. |
| `src/logging.rs`, `Cargo.toml:66-72`, the `/metrics` renderer | `tracing` + `tracing-appender` | BAML's tracer only traces BAML functions inside the BEX VM. We have no BAML functions. Not applicable. |
| `src/egress.rs:279` `evaluate_inference_egress`, `:224` `target_is_loopback` | — | `baml-sys` bypasses this. Disqualifying. |

## 3.7 The strongest case FOR BAML (I am required to make it, and it is real)

**Schema-Aligned Parsing is genuinely good and we have a weaker version of it.**
`src/synthesis/mod.rs:315-320` is a hand-rolled balanced-brace scanner whose own comment admits the problem:
*"Strip a JSON object out of a potentially-noisy LLM response. The model SHOULD emit pure JSON but Gemma 4 /
smaller Ollama models…"*. It handles preambles and braces inside strings (there are tests at `:715-745`), and
if it fails the whole batch is rejected (`:363-390`, all-or-nothing, which is the right fail-closed default but
also a real loss of otherwise-usable verdicts). BAML's `engine/baml-lib/jsonish` is a mature, Apache-2.0,
**pure-Rust**, heavily-benchmarked error-tolerant parser for exactly this — unions, partials, literals, lists,
classes, each with its own bench. On a `local-nli`-absent deployment talking to a small Ollama model, a better
JSON recovery layer would convert some fraction of today's rejected batches into applied ones.

Second: BAML's instinct on observability — "instrument by default, not by exception", typed event values
instead of stringified attributes — is correct, and it is the direction our own `/metrics` surface already
leans (closed-vocabulary labels, constant-cost scrape pinned by
`tests/health_metrics_constant_cost_2579_2583.rs`).

**Neither requires the dependency.** `jsonish` is not published as a standalone crate — only the FFI shims
are on crates.io — so taking it means vendoring an Apache-2.0 Rust library under `THIRD-PARTY-NOTICES`, which
is a bounded, reviewable, exit-free act that shares nothing with adopting a language. The observability
instinct is an idea, and ideas are free.

## 3.8 Vote: REJECT, and the counter-case against my own vote

**REJECT** for v1.0.0 and v1.1.0, as a dependency, a language, or a tracing substrate.

**The strongest case against my REJECT.** BAML is Apache-2.0 with a Rust core, 9.2k stars, daily development,
and founders with real systems pedigree. The licence means a rug-pull cannot take the code we have; a fork is
always available. We will eventually need an observability story richer than a rolling log file, and BAML's is
the most thought-through one in this space. A `WATCH` would cost nothing and would keep the door open, whereas
a `REJECT` risks re-litigating in six months from zero. And my strongest technical objection — the unverified
`dlopen` download — is a property of a *binding*, not of the language; if they publish a pure-Rust crate for
the new engine it evaporates. Someone arguing for `WATCH` over `REJECT` would not be wrong about the facts,
only about the default posture.

I hold `REJECT` because a `WATCH` on a project this loud costs attention we do not have (§5), and because the
two things we would actually want — `jsonish` and an idea — are both obtainable without watching anything.

**What would change my mind, specifically:**
1. A published, reproducible OTel comparison: harness in-repo, named SDK version, named sampler and exporter,
   named hardware, span rate and attribute cardinality, and a stated sampling rate for the baseline. Absent a
   stated sampling rate the claim remains unfalsifiable and I will keep treating it as marketing.
2. A **stable, pure-Rust** crate for the new engine that links at build time, with no runtime download — or a
   download path that fails closed on a missing checksum and honours a single egress predicate.
3. BAML Cloud shipping with published pricing and a self-hostable observability backend under Apache-2.0.
4. A 1.0 with a stated stability policy. Eleven breaking changes nine days before the next minor is the
   disqualifier that has nothing to do with benchmarks.

If all four landed, my vote would be `PILOT` on `jsonish` alone, behind `parse_and_validate`, with the exit
criterion "measurably fewer rejected synthesis batches on a small-model corpus, no change in the
all-or-nothing safety property" — never `ADOPT` of the language.

---

# 4. PAW (ProgramAsWeights)

## 4.1 Licence — this is the finding that ends the discussion

Checked mechanically per artefact class, because a model card licence is not a repository licence.

**Code: MIT.** GitHub API, `orgs/programasweights/repos` — all eleven repos report `license.spdx_id = MIT`
except `.github` (none): `programasweights-python` (MIT, 322 stars), `programasweights-js` (MIT), `wllama`,
`paw-helper`, `skills`, `rules-as-programs`, `claudish`, `pii`, `compile-by-training`, `avatar`.

**Weights and data: NO LICENCE, on every single artefact.** Hugging Face API, `cardData.license`:

| artefact | type | declared licence | downloads |
|---|---|---|---|
| `programasweights/paw-4b-qwen3-0.6b` | **the compiler** (Qwen3-4B-Instruct-2507 finetune) | **null** | 0 |
| `programasweights/paw-4b-gpt2` | the GPT-2-targeting compiler | **null** | 0 |
| `programasweights/paw-programs` | **the published adapters** | **null** | 66,973 |
| `programasweights/paw-base-models` | base interpreters | **null** | 7 |
| `programasweights/Qwen3-0.6B-GGUF-Q6_K` | quantized interpreter | **null** | 1,251 |
| `programasweights/GPT2-GGUF-Q8_0`, `-Q6_K` | quantized interpreters | **null** | — |
| `programasweights/paw-inference-logs` (dataset) | inference logs, records tagged `source: "api"` | **null** | 8 |

**Every artefact we would actually depend on at runtime carries no licence grant.** No licence means no
licence — not "probably permissive". We ship Apache-2.0 to enterprise and government customers with a
`THIRD-PARTY-NOTICES` discipline. We cannot redistribute, vendor, or pre-stage an unlicensed 594 MB base model
plus a 22 MB adapter into a customer's air-gapped install, and we cannot tell an auditor what terms govern the
artefact making a delete recommendation. The paper says *"we do not gate the released artifacts"* (Appendix O)
— an intention, in a CC-BY paper, is not a licence on a weights file. **This is dispositive on its own and
everything below is corroboration.**

I note the contrast honestly: this is a young project that has done the code licensing correctly and simply
not done the weights. It is fixable in an afternoon by the vendor. It is not fixable by us.

## 4.2 The paper's numbers — attacked

Program-as-Weights: A Programming Paradigm for Fuzzy Functions. Zhang, Hotsko, Kim, Nie, Shieber, Deng.
arXiv 2607.02512, submitted 2026-07-02, CC-BY-4.0. I read the PDF locally.

The abstract says PAW *"matches the performance of direct prompting of Qwen3-32B"*. Table 2 (p.7) says
something more specific, and it is not the same thing:

| Method | FuzzyBench | YouTube | SMS (F1) | Yelp | IMDB |
|---|---|---|---|---|---|
| Local LM (Qwen3 32B) | 68.70% | 93.60% | 89.04% | 98.11% | 94.64% |
| **PAW (Qwen3 0.6B)** | **73.78%** | 90.40% | 80.77% | 95.82% | 90.64% |
| delta | **+5.1** | **−3.2** | **−8.3** | **−2.3** | **−4.0** |

**PAW wins on exactly one benchmark: its own.** FuzzyBench is generated by the authors with gpt-5.2 and is the
distribution the compiler was trained on. On all four *external* benchmarks — the ones that were not built by
the people being measured — PAW loses to Qwen3-32B, by 8.3 F1 points on SMS. The abstract's framing is carried
entirely by the home benchmark. That is a legitimate result for a paper; it is not a basis for putting the
artefact on a destructive path.

**Two more numbers from the same table that matter more to us than the headline:**

- `Local LM (gpt-oss-20B)`: **85.45%** on FuzzyBench — beating PAW by **11.7 points on PAW's own benchmark**,
  contained, locally runnable, no hosted compiler, no per-function artefact, a real licence. If the problem
  statement is "we need a local decider for an air-gapped customer", the paper's own table names a better
  answer than the paper's method.
- The `PS` (per-program shipping size) column: prompting baselines ship **0.73 KB** of prompt; PAW ships
  **23 MB** of adapter. That is **~31,500× larger** per function. The entire PAW value proposition is the
  memory footprint of the *interpreter* (1.2 GB vs 60 GB), which is real — but the artefact you version,
  review, sign, ship and audit gets four orders of magnitude bigger, and it stops being text.

**The 22 MB adapter is not a program — the authors say so.** Appendix N, Limitations:

> "Once compiled, the only human-inspectable part of a PAW program is the discrete pseudo-program. The
> continuous PEFT component (LoRA or KV cache) is opaque. We see this as analogous to the inspectability gap
> between source code and compiled binaries; **concrete tools for inspecting and debugging neural binaries are
> an open direction**."

The binary analogy is generous to itself. A compiled binary is deterministic, disassemblable, and its
behaviour on an unseen input is derivable from its instructions. A LoRA delta is none of those. "An open
direction" means: there is no way to know what it does at a decision seam, today, by any method.

And the coupling is a permanent pin:

> "Switching the interpreter (e.g., from Qwen3 0.6B to Qwen3.5 0.8B) requires **retraining the compiler**."

We would be pinned to one interpreter family forever, with the only escape being a retraining run we cannot
perform because the compiler training pipeline is not ours.

**Robustness is measured on noisy *specs*, not on hostile *inputs*.** The paper's robustness result — "under
heavy-typo specifications, performance drops only 4.5 points" — measures tolerance to a sloppy author. Nowhere
does the paper measure what happens when the *input* is adversarial, out-of-distribution, or engineered. Our
synthesis path assumes the input is hostile by construction (`src/synthesis/mod.rs:34-40`: "The curator prompt
may be steered by hostile user content (prompt-injection)"). A 0.6B decoder with no system/user separation —
PAW is literally "one text input, one text output" — has **no trust boundary to put the `<USER_CONTENT>`
envelope on**. Our single most important prompt-level mitigation has nowhere to attach.

## 4.3 The honesty surface — can a compiled adapter abstain?

The three rules it has to meet are in `src/decision.rs` on `origin/f1/3806-w1abc`:

> "1. **Abstain is a first-class value, never a default `false`.** … 2. **Confidence exists only where evidence
> exists.** `confidence` is `Option<f64>`, `None` whenever the endpoint returned no logprobs and no calibration
> evidence backs the number (the #3548 lesson). … 3. **Provenance travels with the answer.**"

Measured against those:

**Confidence: structurally impossible.** PAW is text-in, text-out. The Python SDK, the WASM runtime and the
REST API all return a string. No logprobs are exposed on any surface I found. Our confidence is computed as
`exp(sum logprob)` over the contiguous token run that reconstructs the label. With no logprobs there is no
run, no sum, and no number. Under our own rule the honest outcome is `confidence: None` on **every** PAW
answer, forever. A `confidence < threshold` guard on a destructive seam would therefore never fire, which
means a PAW-backed decider could only ever be wired where confidence is not consulted — which is precisely
*not* the seams #3806 exists to protect.

**Abstain: it emits something, always.** A causal LM with greedy decoding always produces a token. There is no
"no opinion" state in the architecture; PAW has no closed-vocabulary constraint (the paper's own case studies
put the vocabulary in the *prompt* — "Return ONLY one of: exact_match, highly_relevant, somewhat_relevant,
not_relevant" — which is an instruction, not a grammar). So the adapter cannot decline; it can only emit its
best guess, and an off-vocabulary guess is indistinguishable from a confident wrong one at the wire.

Our machinery does handle this correctly — an unparseable or out-of-set answer maps to
`AbstainReason::Unusable`, and the W2 ruling makes abstain terminal and non-destructive. But note exactly what
that means: **the adapter's abstain rate would equal its malformation rate, not its uncertainty rate.** The
cases we most need an abstain for — subtly wrong, well-formed, in-vocabulary answers — are the cases that
sail through as `DecisionSource::DecisionModel` with a clean `Some(verdict)` and no confidence. That is the
worst possible shape: confident-looking, unattributable, and derived from a 22 MB artefact nobody can read.
Compare `src/background/fts_integrity.rs:369`, where we already model the honest tri-state
(`Verified` / `Corrupt` / `Unavailable`) and "could not be completed" leaves the previous verdict untouched.
PAW has no `Unavailable`.

**Provenance: the artefact cannot be reproduced.** `DecisionSource` would say `DecisionModel`, truthfully. But
the audit question at a decision seam that deletes memories is "what did it do, and why". The answer would be:
a natural-language spec we wrote, sent to a third-party hosted compiler, which returned a 22 MB binary tensor
delta that we cannot re-derive, cannot diff, cannot inspect, and cannot explain. Against the North Star —
*data integrity is the highest-order constraint*, *degrade never corrupt*, *destructive ops need explicit
intent and reversibility* — an unreadable, unreproducible artefact on a delete path is the exact failure shape
the North Star names.

**"What happens when the compiled function is wrong in a way the specification did not anticipate?"** — the
paper does not answer this. It has no section on OOD inputs, hallucination, refusal, calibration or confidence
(I grepped the full text for all of them: the only hits for "calibrat" are in two *citations* to other work).
The 73.78% exact-match figure means roughly one in four answers on their own benchmark is not the target. On a
seam whose verbs include `Delete` (`src/synthesis/mod.rs:157`), and where the safety net is a default cap of
**one** delete per batch (`synthesis_max_deletes_per_call`, `src/synthesis/mod.rs:42-46`), a one-in-four error
rate would consume that cap as fast as it is offered.

## 4.4 Supply chain, hosted compilation, and a correction to the premise

**"There is a Rust implementation" — this is not true as stated, and the correction matters.** The
`programasweights` GitHub org contains **zero Rust repositories** (verified: Python ×7, TypeScript ×2,
JavaScript ×1, one language-less `.github`). What exists is `dynamder/paw-rs` on crates.io — `paw-core`,
`paw-candle`, `paw-rs`, MIT. Its own README opens: **"非官方 Rust SDK"** — *unofficial Rust SDK*. Repository
facts: **2 stars, 0 forks, 1 contributor, 56 commits, created 2026-07-18, last pushed 2026-07-22** — i.e.
active for four days, dormant for two months. Combined downloads across all three crates: 911. Its default
backend is **llama.cpp**, a C++ FFI dependency we do not have and would not add under the freeze; `candle` is
an optional feature.

So the Rust production path for PAW is: an unofficial, single-author, two-star, two-month-dormant crate
wrapping unlicensed weights. Under our standard (production components are Rust) this is the only path, and it
is not a path.

**Compilation is hosted, and a spec is project data.** `programasweights.com/AGENTS.md`: *"Compile runs on the
hosted PAW API. Inference should usually run locally through the SDK."* A specification for one of our seams
would necessarily describe our memory semantics — what a contradiction is in our corpus, what makes a memory
stale, when a delete is warranted. Sending that to a third-party endpoint is sending project data to a third
party, which this brief forbids and which `3824-final` forbids independently for anything leaving the host
without our egress predicate's approval. For air-gapped posture 2 (`3806-REQUIREMENTS.md` §2: egress `deny`,
"must open zero sockets") compilation is simply impossible in-place; the customer would have to accept an
adapter compiled elsewhere, by us, that they cannot reproduce, verify, or recompile after a spec change. That
is the opposite of the posture we are building.

**The inference-logs dataset.** `programasweights/paw-inference-logs` is a **public** HF dataset of 3,773
records with fields `spec`, `input`, `model_prediction`, `model_version`, `interpreter`, and `source` — with
`source` valued `"api"`. The card is empty; no collection method, no provenance, no retention policy, no
licence. I could not determine whether this is vendor evaluation traffic or third-party users' hosted-API
requests, and the vendor has published nothing that would let anyone determine it. For a memory product, "we
could not establish whether the hosted API publishes its inference traffic" is a complete answer to whether we
should send anything through it.

**Exit cost.** Low on paper, high in practice. A spec is a paragraph of English — trivially portable. But the
*artefact* is not: if the hosted compiler changes terms, prices, or disappears, every adapter we shipped
becomes unrebuildable, because the compiler weights carry no licence we could rely on to fork them, and
because a new interpreter would require retraining a compiler we do not have. The lock-in is not in the
language; it is in the 22 MB files we would have shipped to customers.

**Maturity.** `programasweights-python` first pushed 2026-03-26, six months old, 322 stars. The paper is ten
weeks old. This is a promising research artefact, not a production substrate.

## 4.5 Where PAW would land in our code — concretely

| Our seam | What PAW would be | Verdict |
|---|---|---|
| `src/decision.rs::DecisionProvider` (W1a, `origin/f1/3806-w1abc`) | a fourth provider beside `chat`, `systemone`, `local-nli` | Cannot satisfy invariant 2 (no logprobs ⇒ never any confidence) and cannot honestly abstain. §4.3. |
| `src/decision_config.rs` `provider = "local-nli"` (W1d, air-gapped posture 2) | the rival to our own local decider | **This is the head-to-head.** W1d is a candle NLI cross-encoder, zero sockets, no hosted compile, no unlicensed weights, and it is already scoped and owned. PAW loses on every axis that matters here. |
| `src/synthesis/mod.rs:157` `SynthesisVerb::{Add,Update,Delete,NoOp}`, `:388` verdict validation, `:42-46` delete cap | the verb decider | The destructive seam. A 73.78%-on-home-benchmark, unreadable, unreproducible artefact does not go here. |
| `src/llm.rs:2131` `classify_kind` | closed-set kind classification over 16 `MemoryKind` variants | Nearest legitimate fit — but `src/llm.rs:2907` `shares_subject_token` shows our pattern: a deterministic guard *gates* the model. PAW adds a model where we are removing our reliance on one. |
| `src/curator/mod.rs:3264`, `src/curator/reflection_pass.rs:1014`, `src/curator/compaction.rs:878` `detect_contradiction` (all reached from `src/autonomy.rs`) | boolean contradiction | Exactly what an NLI cross-encoder is *for*, discriminatively, with a real score. Generative 0.6B decoding is the wrong tool. |
| `src/reranker.rs:11-25` `CrossEncoder::Neural` + `CROSS_ENCODER_FALLBACK_MODEL_SUBDIR` | the local inference runtime | **We already have this.** candle 0.10 + tokenizers + a BERT cross-encoder with a documented air-gapped pre-stage recipe and a `degraded_lexical` fallback that "bails LOUD". PAW would need a Qwen3 causal-LM path plus LoRA merge in candle, in Rust, that does not exist. |

## 4.6 Vote: REJECT, and the counter-case against my own vote

**REJECT** for v1.0.0 and v1.1.0.

**The strongest case against my REJECT.** PAW's thesis is *right*, and it is the thesis our own roadmap
already committed to: compile the judgement once, run it locally, stop paying a cloud round-trip per input.
That is exactly `provider = "local-nli"` under posture 2. The paper is careful, its limitations section is
unusually honest, the compiler-versus-no-compiler ablation (PAW 73.78 vs full fine-tuning 58.40 vs best fixed
LoRA 52.10) is a genuine result that isolates the mechanism, and FuzzyBench is a real contribution. The code
is MIT. Compile is 5–10 seconds. An in-browser WASM runtime is a real engineering achievement. A `PILOT`
advocate would say: the licence gap is a two-line fix the vendor will likely make; run it *offline only*, on a
non-destructive read-path seam with no customer data, with the exit criterion "beats the candle cross-encoder
on a held-out contradiction set" — and if it wins, we have learned something cheap about a direction we are
already taking.

That argument is coherent and I want it on the record. I reject it on three grounds and only three: (a) the
licence is not a formality — until the weights carry a grant there is nothing to pilot that we could ever
ship; (b) we already own the local-decider answer (W1d) and running a second one in parallel splits the
attention of the one lane that is building it; (c) the honest-confidence gap is not a maturity problem that
time fixes — text-out-only is an architectural property, and our rule that confidence requires evidence is not
negotiable.

**What would change my mind, specifically:**
1. A declared, permissive licence on `paw-programs`, `paw-4b-qwen3-0.6b`, and the base-model repos. **This is
   a precondition, not a factor** — without it, nothing else is worth reading.
2. An offline compile path: the compiler runnable locally, so no spec leaves the host and an air-gapped
   customer can rebuild an adapter from its spec.
3. Token-level scores or constrained decoding over a closed vocabulary on the inference surface, so a
   confidence could be attributed under `src/decision.rs`'s rule rather than fabricated.
4. A first-party Rust implementation, or `paw-rs` reaching real maintenance (multiple contributors, sustained
   activity, a candle-default path with no llama.cpp requirement).
5. External validation beyond FuzzyBench showing PAW at or above a contained local baseline on tasks its
   compiler was not trained near — and, for our use, a head-to-head against the W1d cross-encoder on a
   contradiction set.
6. A clear statement of what the hosted API logs and publishes.

With 1, 2 and 3 I would move to `PILOT` behind the `DecisionProvider` seam, offline-only, on a non-destructive
seam, with the exit criterion named in (5). Without 1, the vote is `REJECT` regardless of the rest.

---

## 5. The freeze — plainly

We are in the v1.0.0 GA freeze. `3806-ga-admission.md` records the operator order of 2026-09-19 01:20Z and
states the rule and its price in one sentence: *"Cost stated per the freeze rule. This is a feature, not a
defect, and it is **the first feature admitted since the freeze**."* One exception exists. It has been used.

The load right now, measured: **125 open `ga-blocker` issues, 468 open issues total.** In flight: #3822 (the
internal-network posture that does not exist and is the most common enterprise deployment), #3823 (non-loopback
cleartext refusal, where our own tests currently *pin the defect as a requirement*), the `3824-final`
zero-deviation encryption standard whose largest unit is adding MCP over Streamable HTTPS because stdio cannot
meet the standard, and #3806 W1d/W2 — the local decider and the seam wiring that are the honest answer to the
very problem PAW claims to solve.

**Neither BAML nor PAW belongs anywhere near v1.0.0.** Neither is a defect. Neither closes a `ga-blocker`.
Neither is the admitted exception.

**The cost of the attention alone** is the part worth naming, because it is not zero and it is not
hypothetical. This assessment consumed three agents. A `PILOT` would consume a lane. Every seam either touches
is a seam #3806 is actively rebuilding: a BAML pilot would land in `src/synthesis/mod.rs::parse_and_validate`
and a PAW pilot in `src/decision_clients/`, both of which have open, unlanded, chain-managed work on them
right now (`origin/f1/3806-w1abc` = `271279072`, W1d and W2 unbuilt). Introducing a second design debate into
either while the first is mid-chain is how the #3820 shape happens — a gate nobody was watching. Our own
discipline says a ceiling carried across a rebase is unverified until re-measured; an architectural decision
carried across a mid-chain distraction is worse, because nothing re-measures it.

The correct disposition for both is: **re-assess after GA**, on the triggers named in §3.8 and §4.6, with PAW
gated behind its licence and BAML behind a published methodology and a stable Rust crate.

---

## 6. Evidence ledger — claim / measurement / verified

| Statement | Class |
|---|---|
| "6x faster than OpenTelemetry in Rust, 200x in Python, traces 1000x smaller" | **Vendor claim.** Verbatim at `typescript2/app-website/app/what-is-baml/page.tsx:195`. No methodology found anywhere. Its "Read more" resolves to a generic docs page (`page.tsx:809`). No OTel benchmark exists in the repo; the only profiling bench measures BAML-on vs BAML-off. Their own podcast gives the size mechanism as 8x. |
| "type-definitions cut tokens 60–66%, 6% → 0% failures" | **Vendor claim with a number.** ~2024, Llama2-7B, one task, n=100, Instructor/JSON-Schema-in-prompt baseline, no seeds, no temperature, no code. Fisher two-sided **p = 0.029** (computed by me); Wilson CIs [2.8, 12.5] vs [0, 3.7] **overlap**. Format compliance, not accuracy. |
| PAW 73.78% vs Qwen3-32B 68.70% on FuzzyBench | **Paper measurement**, on the authors' own synthetic benchmark. |
| PAW loses to Qwen3-32B on **all four** external benchmarks (−3.2 / −8.3 / −2.3 / −4.0) | **Paper measurement**, Table 2, read directly from the PDF. |
| gpt-oss-20B scores 85.45% on FuzzyBench, +11.7 over PAW | **Paper measurement**, Table 2. |
| Every PAW model and dataset declares no licence | **Verified by me** — HF API `cardData.license = null` on 7 models + 1 dataset. |
| PAW code is MIT | **Verified by me** — GitHub API, all 10 licensed repos. |
| No first-party Rust PAW; `dynamder/paw-rs` is unofficial (README: 非官方), 2 stars, 1 contributor, dormant since 2026-07-22 | **Verified by me** — GitHub + crates.io APIs. Corrects the premise in the brief. |
| PAW compile is hosted | **Verified** — AGENTS.md: "Compile runs on the hosted PAW API." |
| `baml-sys` / `bridge_rust` download a native `.so` and skip verification when the checksum sidecar is missing | **Verified by me** — source read at `languages/rust/baml-sys/src/download.rs` and `baml_language/sdks/rust/bridge_rust/src/loader/download.rs:3-8`. |
| BAML observability is slated for the unpriced hosted tier | **Verified** — `boundaryml.com/pricing.md`. |
| BAML's legal entity is "Gloo Chat, Inc."; YC-backed | **Verified** — site's own JSON-LD; YC company page. Funding figures: **unverified**, aggregators contradict each other. |
| BAML 0.19.0 ships 11 breaking changes; 0.20.0 released 2026-09-18; nightlies daily; stable Rust crate stale since 2026-04-15 | **Verified by me** — release notes + GitHub releases + crates.io. |
| We run no OpenTelemetry; `tracing` is default-OFF to a rolling file | **Verified in our code** — `Cargo.toml:66-72`, `src/logging.rs:11-13`. |
| We already use type-definition-style prompting at our structured-output seam | **Verified in our code** — `src/synthesis/mod.rs:267-270`. |
| Our decision clients use strict json_schema + logprobs + temperature 0 + fixed seed | **Verified in our code** — commit `271279072` on `origin/f1/3806-w1abc`. |
| We already ship a local candle cross-encoder with an air-gapped pre-stage recipe | **Verified in our code** — `src/reranker.rs:11-25`, `Cargo.toml:218-231`. |
| 125 open `ga-blocker`, 468 open issues | **Verified by me** — `gh issue list`. |
