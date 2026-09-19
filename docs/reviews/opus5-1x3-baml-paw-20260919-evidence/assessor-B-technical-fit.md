# Assessment B — BAML and PAW (ProgramAsWeights)

**Assessor:** B — emphasis: *technical fit against the code we actually have*
**Date:** 2026-09-19
**Tree read:** `/home/fate_two/v07/v09-dev`, `origin/release/v1.0.0` @ `8b4f65a22`, plus the unmerged
`origin/f1/3806-w1abc` @ `271279072` and `origin/f1/3806-w1c` @ `4696658f0`
**Method:** read-only. Nothing installed, no weights downloaded, no third-party code run, no dependency added.
Repo navigated with the `codegraph explore` CLI, plus direct reads and `git show` against the feature branches.
Token figures in §2.3 were produced by reconstructing our own request bodies and measuring them locally.

---

## Votes

| Project | Vote | One-line reason |
|---|---|---|
| **PAW (ProgramAsWeights)** | **REJECT** (as a dependency) | Its output type is `String`. Our `[decision]` slot's output type is `Decision<T>` with `Option<Confidence>`. Adopting it re-introduces the text parse that `#3806` exists to delete, and the `local-nli` slot it would occupy is already specified for a cross-encoder that emits a probability natively. |
| **BAML** | **REJECT** | Its core parser (SAP) *repairs* malformed model output; we *abstain* on it — that is an integrity inversion at a seam that can delete. The Rust path (`baml-sys`) downloads a prebuilt dynamic library at build time by default, against this repo's firmest standing rule and `scripts/check-build-script-vetting.py`. And it is pre-1.0 with eleven breaking changes in the latest minor release. The tracing claim is unsourced and plays no part in this vote. |

Both counter-cases are argued in full below. Neither vote is "this is bad software" — both are "this does not fit
the contract we already wrote."

---

## 0. Two corrections to the brief, established before anything else

These matter because three of the Conductor's questions are phrased on top of them.

**(a) `src/decision.rs`, `src/decision_config.rs` and `src/decision_clients/` do not exist on
`release/v1.0.0`.** Verified: `find /home/fate_two/v07/v09-dev/src -iname '*decision*'` returns exactly one file,
`src/hooks/decision.rs` (an unrelated hook). `git log -S "response_format" origin/release/v1.0.0 -- src/` is
**empty** — the string has never appeared on the release branch.

They exist on two unmerged branches:

- `origin/f1/3806-w1abc` @ `271279072` — `src/decision.rs` (607 L), `src/decision_config.rs` (1010 L),
  `src/decision_boot.rs` (961 L), `src/decision_clients.rs` (679 L) + `chat.rs` (640 L), `calibration.rs` (359 L),
  `fallback.rs` (236 L), `systemone.rs` (419 L), and six `tests/decision_*_3806.rs` files.
- `origin/f1/3806-w1c` @ `4696658f0` — the same minus `decision_boot.rs`.

`271279072` is the same commit `#3824` cites for its measured plaintext-loopback inventory, so W1a/W1b/W1c are
real, reviewed-in-lane work awaiting a landing, not a design. **W1d is the only unbuilt unit**, and I found its
seam already cut (§1.2). Everything I say about "our structured-output work" below refers to that branch; on
`release/v1.0.0` today there is nothing to displace, which by itself answers part of the BAML question.

**(b) There is no 64 KiB cap on the `/metrics` renderer.** `crate::metrics::render()`
(`/home/fate_two/v07/v09-dev/src/metrics.rs:1418`) is an unbounded `TextEncoder` encode; the handler
`prometheus_metrics` (`/home/fate_two/v07/v09-dev/src/handlers/transport.rs:1348-1362`) returns the whole body
with no length limit. The `64 * 1024` literals in the tree are `axum::body::to_bytes` read limits in
`src/handlers/errors.rs:345` and in tests, plus `MAX_CONTENT_SIZE = 65536` for memory content. Worth correcting
because "the /metrics 64 KiB cap" was offered as a place BAML's small-trace claim might land, and it is not one.

---

## 1. PAW (ProgramAsWeights)

### 1.1 What it is — verified

Compiles an English specification into a LoRA adapter for a frozen small interpreter. Established against the
sources:

- **The paper is real and its result is good.** arXiv 2607.02512, *"Program-as-Weights: A Programming Paradigm
  for Fuzzy Functions"*, Zhang, Hotsko, Kim, Nie, Shieber, Deng; submitted 2 July 2026. A 4B compiler trained on
  a 10M-example set (FuzzyBench) emits adapters for a frozen 0.6B Qwen3 interpreter; the abstract's measured
  claim is that the 0.6B interpreter running a PAW program "matches the performance of direct prompting of
  Qwen3-32B, while using roughly one fiftieth of the inference memory and running at 30 tokens/s on a MacBook
  M3." That is a *measurement*, and it is the strongest thing in this assessment in PAW's favour.
- **The contract is text-in / text-out.** `AGENTS.md`: "Each function takes a single text input and returns a
  single text output." Closed-vocabulary behaviour is obtained by *asking nicely in the spec* — AGENTS.md's own
  guidance is to write "Return ONLY one of: X, Y, Z". There is **no schema validation, no grammar, no logprob
  surface** described anywhere in the docs, the paper abstract, or the Rust API (§1.4).
- **Context is ~2048 tokens for spec + input + output combined**, and "Inputs that exceed it will error."
- **Compile is a hosted service.** The Python README documents `PAW_API_KEY=paw_sk_…` / `paw login`; compilation
  goes to their API and returns a slug/id. AGENTS.md documents the signature as
  `paw.compile(spec, compiler=None, slug=None, public=True)` — **`public=True` is the documented default**, i.e.
  the specification you compile is published by default. Separately, `huggingface.co/datasets/programasweights/
  paw-inference-logs` publishes 3,773 rows of inference inputs and model outputs. I did not run anything, so I
  cannot say whose inputs those are; I can say that a product whose compile step defaults to public and whose
  hosted inference has a public log dataset is not a thing to point at a memory substrate.

### 1.2 Licence findings

| Artefact | Licence | Evidence | Confidence |
|---|---|---|---|
| Python SDK repo | **MIT** | GitHub repo footer + Links section; README licence section says "MIT" | High |
| `paw-core`, `paw-candle` (and siblings) | **MIT** | crates.io API: every published version 0.1.0→0.3.0 carries `license: MIT` | High |
| Qwen3-0.6B base | **Apache-2.0** | `huggingface.co/Qwen/Qwen3-0.6B` model-card `license: apache-2.0` | High |
| GPT-2 base | **MIT** | `huggingface.co/openai-community/gpt2` model-card `license: mit` | High |
| **`paw-4b-qwen3-0.6b` (the compiler)** | **COULD NOT BE DETERMINED** | Model card shows no YAML `license:` tag and no licence prose. It states only that "the cleaned compile/runtime code and the arXiv preprint will be public by Jul 6, 2026" | — |
| **`paw-programs`, `paw-base-models`, the GGUF repos, `paw-inference-logs`** | **COULD NOT BE DETERMINED** | No licence tag visible on the org listing or the cards I read | — |
| **The generated adapters** | **COULD NOT BE DETERMINED** | Nothing in AGENTS.md, the README, or the model cards states who owns or licenses a compiled `.paw` artefact, and `public=True` implies a publication right they have not defined | — |

The bases are clean. The compiler and the adapters — the two artefacts we would actually ship or generate — are
not established. That is a finding, not a gap in my search: I read the org page, the compiler card, the dataset
card and both SDK READMEs.

**The Rust implementation exists but is not first-party.** `paw-core`, `paw-rs`, `paw-candle`, `paw-llamacpp`
all resolve to `github.com/dynamder/paw-rs`, whose README opens in Chinese with **非官方** — *unofficial*. 2
stars, 56 commits, first published 2026-07-18, current 0.3.0 (2026-07-22), `paw-core` has **438 total downloads**
and `paw-candle` **143**. The operator's note that "there is a Rust implementation" is correct in letter and
misleading in weight: it is one person's two-month-old unaffiliated wrapper.

### 1.3 Where it would land — the concrete seam, and it is already cut

This is the finding I was asked for and it is sharper than I expected.

On `origin/f1/3806-w1abc`, `src/decision_config.rs:57-63`:

```rust
/// Canonical selector for the in-process NLI cross-encoder decision
/// provider (W1d). Opens no socket, carries no credential, and resolves
/// its weights from a local path — so `base_url` and every `api_key_*`
/// key are REFUSED for it.
pub const PROVIDER_LOCAL_NLI: &str = "local-nli";
```

and the validator enforces it (`src/decision_config.rs:357-378`) — configuring `base_url`, `api_key_env` or
`api_key_file` alongside `provider = "local-nli"` is a hard `bail!` with the message *"that provider runs in
process, opens no socket and carries no credential."* `ResolvedDecision::is_local()` (`:213`) keys off it and
`base_url` resolves to the empty string (`:393`). `grep LOCAL_NLI src/decision_boot.rs` returns **nothing** — the
alias is reserved, validated, and unimplemented.

So the question is not "where would PAW go" but "would PAW be a legitimate occupant of this already-specified
slot". The slot's specification is: **in-process, no socket, weights from a local path, returns
`Decision<T>`.** PAW via `paw-candle` satisfies the first three. It fails the fourth, and the fourth is the
whole point.

**Why "no socket" is load-bearing and not a nicety.** `#3824` (operator ruling, 2026-09-19, zero deviations) makes
every network transport encrypted *including loopback*, and `#3830` names the local-model TLS cliff as "the
single largest usability risk in the whole encryption programme." An in-process decider is the only decider
design that is *structurally* outside that problem — it has no transport to encrypt. `src/egress.rs:89` on the
branch already carries `EgressClass::InferenceDecision`, and `DecisionEgressGuard::check_outbound`
(`src/decision_boot.rs:244-264`) runs `evaluate_inference_egress` against it. A `local-nli` provider bypasses
that guard by having nothing to guard. Both PAW-in-process and an NLI cross-encoder earn that; a PAW *sidecar*
(the Python SDK, the hosted API) does not, and would land straight back in the `#3824`/`#3830` cliff.

**The other seams PAW would touch, by file and symbol, all on `release/v1.0.0`:**

- `OllamaClient::classify_kind` — `/home/fate_two/v07/v09-dev/src/llm.rs:2131`, prompt
  `classify_kind_prompt` at `:850`, system const `CLASSIFY_KIND_SYSTEM` at `:841`, parser
  `parse_classified_kind` at `:857`. The parser scans alphabetic tokens and returns the first that names a kind;
  no token naming a kind ⇒ `None` ⇒ abstain. Consumers: `crate::autonomy::classify_kind`
  (`src/autonomy.rs:143`, via the `AutonomyLlm` trait), called from
  `src/curator/transcript_classify_pass.rs` and `src/reload.rs`.
  *Extra defect codegraph surfaced that `#3806` also names:* `CLASSIFY_KIND_SYSTEM` enumerates **8** kinds
  (`observation, decision, claim, event, concept, entity, relation, conversation`) while `MemoryKind`
  (`src/models/memory.rs:64-147`) has **16** and `parse_classified_kind` accepts all 16. The prompt and the
  parser disagree about the vocabulary today.
- `OllamaClient::detect_contradiction_async` — `src/llm.rs:2900`. After a deterministic
  `shares_subject_token` pre-gate, it does `Ok(answer.starts_with("yes"))`. Signature is `Result<bool>`:
  **there is no abstain value in the type.** Refusals, preambles, an empty body and a genuine "no" are the same
  `false`.
- Synthesis — `crate::synthesis::synthesise_with_cap` (`src/synthesis/mod.rs:454`) builds one prompt over **N**
  candidates and `parse_response` fans out N `Verdict{verb, merged_content, reason}`
  (`src/synthesis/mod.rs:152-185`); consumed by `run_synthesis_pass`
  (`src/mcp/tools/store/synthesis.rs:203`) which drives `updates`/`deletes` under the SEC-1 delete cap and a
  per-verdict K9 re-check.
- Curator merge gate — `CONSOLIDATE_JACCARD_THRESHOLD = 0.55` (`src/autonomy.rs:65`) AND
  `CONSOLIDATE_COSINE_THRESHOLD = 0.75` (`:78`), applied at `src/autonomy.rs:521` and `:542`.
- **Wake plane / `rust-a2a` (asked explicitly by #3842): a clean, confident NO.** `src/wake_hub/` (16 files),
  `src/wake_client/`, `src/wake_sink/` total 11,754 lines of CBOR framing (`codec.rs`, `frame.rs`), Ed25519
  scoped delegation (`delegation_verifier.rs`, `src/identity/hub_delegation.rs`, `A2A_HUB_SCOPE` at `:96`),
  routing, limits and histogram metrics. `grep -rn "OllamaClient\|llm::" src/wake_hub src/wake_client
  src/wake_sink` returns **zero hits** — the plane makes no inference call of any kind. There is no fuzzy-text
  decision anywhere in it. PAW does not apply, and neither does BAML.

### 1.4 The Conductor's question, answered: better, worse, or a different shape?

**A different shape, and on the one axis that matters, a worse one.**

Our contract, from `src/decision.rs` on `origin/f1/3806-w1abc`:

- `Decision<T>` (`:228`) with `decided(value, confidence: Option<f64>, source)` (`:244`) and
  `abstain(reason: AbstainReason, source)` (`:256`) — abstain is a *constructor*, not a sentinel.
- `Confidence(f64)` (`:142`) with a fallible `new()` (`:149`).
- `AbstainReason` (`:95`) and `DecisionSource` (`:62`) so `/capabilities` reports honestly.
- `DecisionProvider` (`:372`) → `choose`/`score`/`judge`.

`paw_rs`'s entire inference surface is:

```rust
let mut f = PawFnBuilder::builder().slug("email-triage").load().await?;
let result = f.run("Urgent: server is down!")?;   // -> String
```

and `paw_candle`'s is `func.run(prompt, &PawRuntimeOptions::default())? // -> String`. **One string in, one string
out.** So adopting PAW means: we get a local, offline, fast producer of *a string*, and then we must write
`parse_classified_kind` again on the other side of it. That is verbatim the defect `#3806` was admitted to GA to
remove. The claim "typed decision over a closed vocabulary" would be carried by a sentence in an English spec and
enforced by nothing.

Worse, **confidence is unobtainable, not merely absent.** Our branch is uncompromising about this — `chat.rs`
emits a confidence only when exactly one contiguous run of returned tokens reconstructs the decided label
exactly, `exp(Σ logprob)` over that run, and reports *no* confidence in five enumerated cases including "the
request did not ASK for logprobs, so anything in that field was volunteered … and cannot be vouched for". A
`String` return type exposes no logits. Under our own rule — confidence absent unless evidence exists — a PAW
decider would be a permanently `None`-confidence provider. Every threshold `#3806` specifies (the
low-confidence-`Delete`-collapses-to-`NoOp` rule, the merge judge as a narrowing third gate) is inert against a
provider that can never clear a floor.

**The NLI cross-encoder (W1d) is structurally the right shape, and we already own the machinery.** A
sequence-classification cross-encoder's *native output is the number*: a 3-way head over
entail/neutral/contradict is exactly `Choice` over a closed vocabulary with a real probability, and its binary
reading is exactly `Judgement{verdict: Option<bool>, confidence: Option<f64>}`. No text is generated, so no text
is parsed. And `src/reranker.rs` already contains every hard part:

- `CrossEncoder::Neural { model: Arc<BertModel>, tokenizer, batch_tokenizer, classifier_weight,
  classifier_bias, device }` (`src/reranker.rs:930-963`) — **we already carry a classification head on a candle
  BERT and read its logits.**
- `resolve_cross_encoder_files` (`:1076`) + `load_cross_encoder_from_fallback` (`:1109`) — a fully built
  **air-gapped** loader: honours `AI_MEMORY_EMBED_OFFLINE`/`HF_HUB_OFFLINE`, scans every `snapshots/*` leaf so a
  hand-staged air-gap layout *and* a previously-online cache both resolve, and **bails loud** naming the repo dir
  and model id rather than making a silent network attempt (`:1129`).
- Degrade-never-corrupt already wired: `new_neural()` (`:990`) falls back to `Lexical { degraded: true }`, emits
  the `reranker.fallback` tracing event, and the degrade is surfaced in-band — `capabilities.rs:359-371` flips
  `features.cross_encoder_reranking` to `false` and annotates `models.cross_encoder` as `lexical-fallback`.
- `warm_up()` (`:1031`), `BatchedReranker` (`:1910`), mutex-free `Arc` forward, pool sizing, budget
  (`ENV_RERANK_BUDGET_MS`), seq caps.

W1d is a second head in a pipeline that is already offline-capable, already honest about its own degradation,
and already tested for the air-gap. PAW would require standing up a **second, incompatible** model stack beside
it (see §1.5). That is the whole answer: PAW is not a better answer or a worse answer to the same question — it
answers a question about *generation* while `#3806` asks a question about *measurement*.

### 1.5 Cost and risk

1. **Two candle stacks in one binary.** We pin `candle-core/nn/transformers = "0.10"`, `hf-hub = "0.5"`,
   `tokenizers = "0.22"` (`Cargo.toml:219-231`). `paw-candle` requires `candle-* ^0.11` and `paw-rs` requires
   `hf-hub ^1.0`. 0.10 and 0.11 are semver-incompatible, as are hf-hub 0.5 and 1.0, so cargo compiles **both** —
   two full tensor stacks, two gemm backends, two hub clients, in a binary whose release profile comments
   (`Cargo.toml:552`) already name candle/gemm as the dominant compile cost. The alternative is upgrading our
   candle to 0.11 across `src/reranker.rs` (4,822 L) and `src/embeddings.rs` on behalf of a 2-star crate.
2. **Supply chain.** `scripts/check-git-dependency-sources.sh` exists because `alphaonedev/paste` was **deleted
   out from under a pin** and broke the build with nothing in this repo having changed. `paw-*` is on crates.io
   so the gate passes mechanically — and the hazard class is identical: one unaffiliated maintainer, 438
   downloads, 0.3.0, two months old, no second contributor named. Four new direct deps plus their closure, into
   a `Cargo.toml` that today carries 135.
3. **Compile is remote and public by default.** Any spec we compile goes to their API under an API key, with
   `public=True` documented as the default. Our decision policies encode what we will and will not delete.
4. **The artefact is unreviewable *and* irreproducible.** `#3842` asks how anyone would know what a 22 MB adapter
   does at a seam that can delete memories. Honest answer: the same way they know what our 80 MB MiniLM does —
   they don't, and both are bounded by the same structural rule (`#3806`: "the decider may only NARROW a
   destructive path"; `src/mcp/tools/store/synthesis.rs:268-270`: the verdict is advice, the deterministic
   pipeline is authoritative). So opacity alone is not disqualifying. What *is* different: our cross-encoder is a
   published, checksummable, stable artefact with a model card; a PAW adapter is produced by a nondeterministic
   4B compile of an English sentence, with no documented way to diff two adapters or to prove that the adapter
   you audited is the adapter you shipped. `scripts/check-install-checksum.sh` has nothing to pin.
5. **2048-token total context kills the highest-value seam outright.** Synthesis is a batch: N candidates at
   `DEFAULT_MAX_CANDIDATE_CHARS = 1500` each (`src/synthesis/mod.rs:97`) plus the incoming memory, answered with
   N verdicts including free-text `merged_content`. Spec + input + output share ~2048 tokens. Three candidates
   overflow it. PAW cannot do synthesis at all, and `#3806` names synthesis as the HIGH-value seam.

### 1.6 Vote — **REJECT** (as a dependency)

Reject `paw-*` as a crate, the Python SDK as a component, and the hosted API as a backend. The *silhouette* —
a small, frozen, offline, local model behind a typed seam — is right, and it is already the specification of
`PROVIDER_LOCAL_NLI`. Build W1d.

**Revisit trigger:** if PAW ships a first-party Rust runtime that returns per-label logits or constrained-decode
probabilities rather than a `String`, publishes a licence for the compiler and the generated adapters, and offers
offline compilation, it becomes a candidate implementation *behind* the `local-nli` alias — the seam is the right
one, the API is not.

### 1.7 The strongest case against my own vote

1. **The paper's number is better than anything W1d will produce, and it is measured.** A 0.6B interpreter
   matching Qwen3-32B direct prompting is a serious result. An NLI cross-encoder is a 2019-era artefact and will
   be worse at the seams that are genuinely semantic — the curator merge judge is closer to "would a careful
   person merge these" than to "does A entail B", and NLI is a poor proxy for that. I am choosing a weaker model
   because its output type is honest. That is a real trade and I should name it as one.
2. **`local-nli` names an implementation in a config constant, which is itself a smell.** The alias bakes "NLI
   cross-encoder" into the wire-visible configuration surface. If W1d turns out to underperform, the alias is
   already frozen and a better local decider has to either lie about its name or add a second alias. A vote that
   defends `local-nli` is partly defending a naming decision rather than an engineering one.
3. **Constrained decoding is available and I under-weighted it.** The PAW Python README mentions llama.cpp
   compatibility for constrained decoding, and `paw-llamacpp` exists. A GBNF grammar over 16 labels plus the
   llama.cpp logprob surface *would* give a typed choice with a probability. I could not verify that `paw-rs`
   exposes it — `run()` returns `String` and docs.rs reports the crate 21.43% documented — but "the docs don't
   show it" is weaker evidence than "it isn't there."
4. **W1d is unbuilt and unestimated.** I am arguing against a working artefact in favour of code that does not
   exist, on a GA-frozen branch, with `#3806` itself estimating ~17-19 engineering-days for the whole slot.

**What would change my mind:** a `paw-*` (or first-party) API returning per-label probabilities over a closed
vocabulary; a stated licence for the compiler and adapters; offline compile; and a held-out comparison on our own
seams where PAW beats an NLI cross-encoder by enough to justify a second candle stack.

---

## 2. BAML

### 2.1 What it is, and the licence

Apache-2.0 (GitHub repo). "The programming language for agents": a `.baml` DSL with a Rust-like type system,
a code generator emitting clients for TS/Py/Go/C#/Java/Rust, a built-in test/eval framework, and
Schema-Aligned Parsing. Rust crates published by BoundaryML: `baml` 0.221.0 (12,183 downloads), `baml-sys`
0.221.0 **Apache-2.0**, created 2026-01-07 (11,599), `baml-macros`, `baml_bridge`, `baml-cli`. Mature, real,
widely used. Licence is clean and is not the problem.

### 2.2 Would adopting BAML replace, complement, or duplicate our structured-output work?

**Duplicate — and downgrade.** Here is exactly what would be deleted, and why each deletion is a loss.

On `origin/f1/3806-w1abc`, the code BAML would displace is `src/decision_clients/chat.rs` (640 L),
`src/decision_clients.rs` (679 L), `src/decision_clients/fallback.rs` (236 L) and parts of
`src/decision.rs` (607 L) — roughly **1,600-2,100 lines**, plus `tests/decision_clients_3806.rs` and
`tests/decision_client_secret_redaction_3806.rs`. What goes with them:

| Property we have | Where | What BAML gives instead |
|---|---|---|
| Abstain as a first-class **constructor**, with a typed `AbstainReason` | `src/decision.rs:95, :256` | A parse error or an exception. `Decision<T>` has no BAML analogue; the closest is `Option`/error, which is the sentinel we deliberately refused. |
| Confidence **only** from requested logprobs, with five enumerated no-confidence cases and a one-way latch | `src/decision_clients/chat.rs:24-56, :330-336, :300-326` | No logprob-derived confidence surface I could find. BAML's `Collector` reports calls, timing and HTTP; not token probabilities. |
| `AbstainReason::Unusable` on any output that is not exactly one option | `chat.rs:352-358` via `strict_option_match` (`src/decision_clients.rs:262`) | **SAP**, which "extracts the structured data the model clearly intended to produce, and returns a typed object … no retry required" — a repairing coercer with a Strip → Fix → Parse → Align → Coerce → Validate pipeline. |
| Credential redaction proved by test: manual `Debug` reporting key presence only, endpoint as redacted origin | `chat.rs:125-140`, `tests/decision_client_secret_redaction_3806.rs` | Would have to be re-established against a foreign runtime. |
| Egress chokepoint per call: `EgressClass::InferenceDecision` + `check_outbound` on **every** request including the latch retry | `src/egress.rs:89`, `src/decision_boot.rs:244-264`, `chat.rs:151-153` | A foreign HTTP client we do not own, which the `#1963` gate cannot see. |
| `temperature = 0` + fixed `seed = 3806` so a calibration figure measured once still describes the system | `src/decision_clients.rs:114-120` | Configurable, but ours is a constant with a stated reason. |

**The SAP row is the disqualifying one.** Our entire posture is *fail closed, degrade never corrupt*: unusable
output becomes an abstain, and an abstain is terminal. SAP's purpose is to convert unusable output into a typed
value by inference about intent. At `src/mcp/tools/store/synthesis.rs` a repaired verdict is a `Delete` we did
not actually receive. A parser that guesses is the single worst component to install in front of a destructive
seam, however good it is at guessing.

So: not a replacement (it does less of what we need), not a complement (it occupies the same seam). It is a
duplicate that trades our integrity properties for its ergonomics properties.

### 2.3 Type-definition prompting — the Conductor's four questions, measured

**(1) What do we send today, and what does the schema cost?**

`OpenAiCompatibleDecider::request_body` (`src/decision_clients/chat.rs:227-266`) puts the schema in
`response_format`, **not in `messages`**:

```rust
"response_format": {"type": "json_schema", "json_schema": {
    "name": SCHEMA_NAME, "strict": true,
    "schema": {"type":"object", "properties": {field: property},
               "required": [field], "additionalProperties": false}}}
```

with `schema_for` (`:193-210`) emitting `{"type":"string","enum": options}` for `Choose`,
`{"type":"string","enum":["yes","no"]}` for `Judge`, `{"type":"number","minimum":…,"maximum":…}` for `Score`.

I reconstructed those exact bodies and measured them (bytes are exact; token counts are WordPiece from the
locally cached `cross-encoder/ms-marco-MiniLM-L-6-v2` tokenizer — a **proxy**, not the GPT BPE a vendor would
bill, and WordPiece over-counts JSON punctuation, so treat these as an upper bound on the shape):

| Payload | bytes | WordPiece (proxy) |
|---|---:|---:|
| `response_format` for `classify_kind`, 16 `MemoryKind` variants | 375 | 168 |
| its inner `schema` object alone (what Instructor would inline) | 285 | 121 |
| our system message for the same call (`SYSTEM_PREAMBLE` + `"Allowed values: a \| b \| …"`) | 327 | 72 |
| a BAML-style TS type definition for the same 16-way choice | 232 | 74 |
| `response_format` for `Judge` (`yes`/`no`) | 222 | 112 |
| its system message | 172 | 44 |

Two things fall out. First, **we already send the compact form in the prompt**: 327 bytes / 72 proxy-tokens of
`"Allowed values: observation | reflection | …"` versus 285 bytes / 121 proxy-tokens for the inlined JSON Schema
that BAML's post is arguing against. Our system line is *shorter in tokens than the schema it replaces* and is
within noise of BAML's own TS rendering (232 B / 74). Second, against the payload it rides with — a memory
`content` up to `MAX_CONTENT_SIZE = 65536`, or 1,500 chars at the synthesis candidate cap — the schema is between
~16% (capped candidate) and well under 0.5% (a full memory) of the request. A 60% cut of that is not material on
a store or recall path.

And whether `response_format` is billed as input tokens at all is provider-specific; I did not verify it and will
not assert it. What is certain and sufficient: it is **not prompt text competing for the model's attention**,
which is the mechanism behind BAML's failure-rate result. `chat.rs`'s own comment says the system line exists
"only for endpoints that treat `response_format` as advisory" — we keep the compact restatement precisely as a
belt on top of the braces.

**(2) Does their failure mode cost us an abstain or a wrong answer? An abstain — verified by tracing the code.**

Their failure is a model emitting `{"type":"integer","value":85}` instead of `85`. Trace that through
`read_structured_answer` (`chat.rs:395-420`): `document.get("choice")` → `None` → `?` → `None` →
`CallFailure::Abstain(AbstainReason::Unusable)` (`chat.rs:288`). And if the model echoed the schema *inside* the
right key, `strict_option_match(raw, options)` (`chat.rs:354`) fails against the closed vocabulary → abstain
again. Non-JSON prose: `serde_json::from_str(content).ok()?` → `None` → abstain.

**Every path is an abstain. There is no path to a wrong answer.** Under our rules a 6% failure rate is a 6%
abstain rate; under `#3806`'s constraint that the decider may only *narrow* a destructive path, 6% abstains means
6% fewer narrowings — at `classify_kind` the kind stays `Observation`, at synthesis the verdict collapses toward
`NoOp` and the row is inserted rather than merged. The cost is duplicate accretion and lost optimisation, never
corruption. So BAML's headline reliability claim buys us **availability, not integrity** — and the North Star
says integrity is the constraint and availability is the tradeable. Real value; bounded value; not worth a
language.

**(3) Can we take the idea without the product? We already did.**

`OpenAiCompatibleDecider::system_prompt` (`chat.rs:213-226`) *is* type-definition prompting — the closed
vocabulary restated as `a | b | c`, with a bare preamble and no schema boilerplate. Rendering it as
`{ choice: "observation" | "reflection" | … }` instead measured 232 B / 74 proxy-tokens against our 327 B / 72:
**more bytes, the same tokens, no measurable win.** The change would be one function body (~14 lines), displacing
nothing, gaining nothing I can measure. My recommendation is to leave it and to note in `chat.rs`'s module
comment that the compact restatement is deliberate and independently converged with BAML's published result —
so a future reviewer doesn't "improve" it back into a schema dump.

Adopting BAML the language, by contrast, costs: a `.baml` source set and a code generator in the build (a
third language beside "scripts are Python, production components are Rust"), the `baml`/`baml-sys`/`baml-macros`
dep closure, the deletion in §2.2, re-proving secret redaction and the `#1963` egress gate against a foreign HTTP
client, and — decisively — **`baml-sys` is "BAML FFI bindings with runtime dynamic library loading" with a
`download` feature enabled by default and a `no-download` opt-out.** `scripts/check-build-script-vetting.py`
exists to enforce "no external code injection. EVER.", written after an external party attempted exactly this
vector; and `scripts/check-install-checksum.sh` and the air-gapped posture both assume the build fetches no
binaries. A default-on prebuilt-binary download is a structural conflict, not a configuration detail.

**(4) Where their benchmark does not reach us.**

Their test is **Llama 2 7B**, 100 runs, JSON Schema text injected into the prompt via Instructor, versus a TS-like
type definition also in the prompt. The post's own caveat: "we are only talking about the actual schema." They
explicitly did **not** compare against native structured output, function calling, or constrained decoding.

Our path is on the far side of that omission. We send `response_format: json_schema` with `strict: true`, which
on a compliant endpoint is compiled to a server-side grammar — an off-vocabulary answer is *structurally
impossible to emit*, not merely discouraged; plus `temperature = 0` and `seed = 3806`. Their measured 6%→0% is
the delta between two *unconstrained* prompting styles, and their failure mode is precisely the one a strict
grammar removes. **The number does not transfer to our path.**

Where it retains some force: endpoints that treat `response_format` as advisory — Ollama's OpenAI surface,
llama.cpp, an older vLLM. `chat.rs` already anticipates exactly this and the mitigation it chose is the compact
vocabulary restatement, i.e. BAML's technique, applied at the only place it still matters. The engineering
judgement was already made correctly; this post is corroboration, not new information.

### 2.4 The tracing claim — unsourced, and I do not carry it into my technical case

**Stated plainly: the claim is unsourced and I am not treating it as evidence for or against anything.** The
numbers ("6x faster than OpenTelemetry in Rust, 200x faster in Python, traces 1000x smaller", "traces every
function instead of sampling") appear on `boundaryml.com` marketing only. Not in the GitHub README. Not in the
latest release notes (0.19.0, posted ~8 days ago), which contain **no tracing or OpenTelemetry content at all**.
**No methodology, benchmark repository, or backing blog post could be found** — I searched for one specifically.
`BoundaryML/tc-benchmark` is a structured-output/tool-use *model* benchmark, not a tracing benchmark. My BAML
vote does not rest on this claim in either direction; §2.2, §2.5 and §2.6 are the case.

**A pattern worth flagging to the Conductor about how to read this vendor's numbers.** The one quantity offered
in 0.19.0 is "5,876 (5.9%)" fewer *displayed O2 bytecode instructions* across the standard library and test
scaffolding — a **static instruction count, not a throughput measurement**. "Traces 1000x smaller" is likewise a
*size*, not a rate. Both are structural counts presented in performance framing. That does not make them false;
it means a reader should not convert them into an expectation about wall-clock behaviour, and it lowers my prior
that the 6x/200x figures were produced by a controlled benchmark rather than a favourable comparison.

**What the tracing claim plausibly measures, inferred and labelled as inference:** the docs describe `@trace` as
making a function's input and output "show up in the Boundary dashboard"; `boundaryml.com/pricing.md` says the
local toolchain "runs on your machine and does not call Boundary's servers" while "BAML Cloud is coming later
this year, adding hosted capabilities for: Observability, Team controls, Governance"; and the `baml` crate's
deps include `prost` (protobuf). The plausible reading is a purpose-built binary span format for one workload
(an LLM call with known fields) against a general-purpose OTel SDK plus OTLP export. A fair engineering result
for their workload; not a general statement about tracing; and, for us, moot — see below.

**What in our tree would benefit: nothing, and the comparison does not apply to us.** Verified by grep across
`Cargo.toml`, `Cargo.lock` and `src/`: **there is no `opentelemetry`, `tracing-opentelemetry`, `otel`, `otlp` or
`jaeger` anywhere.** The only hits are in `docs/`, and they are *decisions not to*:

- `docs/v1.0.0/UPDATED-ROADMAP-…:519` — "OpenTelemetry | **CUT** from property gate"
- `…:595` — "Opt-in OTel; reject default OTLP"
- `…:875` — "Default OTLP phone-home | — | **PERMA-BAN** — opt-in OTel only (W5-A5)"
- `docs/v1.0.0/perfect-endpoint-assessment/w7-a2-v1-epic-dag.md:333` — H1 is a post-v1.0 epic

What we run instead: `tracing = "0.1"` + `tracing-subscriber = "0.3"` (`env-filter`, `fmt`, `json`) +
`tracing-appender = "0.2"` (`Cargo.toml:66-72`), initialised in `src/logging.rs::init_file_logging` (`:162`) and
`init_console_tracing` (`:134`), with an optional RFC-5424 syslog sink behind the `syslog` feature; and a
Prometheus registry rendered by `crate::metrics::render()` (`src/metrics.rs:1418`) at `/metrics`
(`src/handlers/routes.rs:128` → `src/handlers/transport.rs:1348`). Structured JSON lines to a local file and a
scraped counter registry. **We are already at "zero OTel overhead" and already at "no phone-home", which is where
BAML's tracing is trying to get to from the other direction.** Being 6x faster than a thing we do not run is not
a benefit we can bank, and the destination BAML's `@trace` targets (a hosted dashboard) is the thing our roadmap
perma-banned.

### 2.5 The provider abstraction — would BAML remove our branching, or relocate it?

**It would relocate a branch that is already one line, and add a language above it.** Measured, not asserted.

*What we branch on today.* `LlmProvider` (`/home/fate_two/v07/v09-dev/src/llm.rs:432-444`) has exactly **two**
variants:

```rust
pub enum LlmProvider {
    Ollama,                                 // POST /api/chat, /api/embed, no auth header
    OpenAiCompatible { api_key: String },   // POST /v1/chat/completions, Bearer
}
```

and the doc comment on the second variant enumerates what rides in it: "xAI Grok, OpenAI, Anthropic (via OpenAI
shim), Google Gemini, DeepSeek, Kimi, Qwen, Mistral, Groq, Together, Cerebras, OpenRouter, Fireworks, LMStudio,
vLLM, llama.cpp server, and any other vendor following the spec." **Seventeen-plus named vendors, one variant.**
The only per-vendor knowledge in the client is a route string and an auth header; there is no
`match vendor { Anthropic => …, Gemini => … }` anywhere. `is_ollama_native()` (`src/llm.rs:1465`) is a single
`matches!` and its only job is to stop callers reusing the chat client for the Ollama-shaped `/api/embed`
(`:1457-1463`).

In the decision path it is narrower still. `src/decision_clients/chat.rs` has **exactly one** provider branch,
at construction (`:148-156`):

```rust
let route = if resolved.provider == crate::llm::BACKEND_OLLAMA { OLLAMA_CHAT_ROUTE } else { CHAT_ROUTE };
```

`OLLAMA_CHAT_ROUTE` is `/v1/chat/completions` on the *local* server — and the comment at `:79-84` says why:
"Ollama's NATIVE `/api/chat` carries neither `response_format: json_schema` nor `logprobs`, so the decision
client uses its OpenAI-compatible surface instead." So the single branch we have is not vendor taxonomy; it is a
**capability** decision, chosen once, to route to the surface that can actually constrain and measure the answer.
Everything downstream — `schema_for`, `system_prompt`, `request_body`, `read_structured_answer`,
`label_probability` — is provider-agnostic.

*What BAML's own 0.19.0 notes say about its abstraction.* Under "Agent journals use structured content blocks":

> "Provider support differs. Gemini/Vertex accepts all four media kinds in user turns and tool results.
> Anthropic accepts images and PDFs. OpenAI Responses accepts user images, audio, and PDFs; tool audio is moved
> to a following user turn. OpenAI Chat moves tool media to a following user turn. Bedrock accepts all four
> user-media kinds and moves tool audio to a following user turn. Unsupported kinds are rejected."

Five named provider behaviours the consumer must hold in their head, with silent turn-reordering in two of them
and hard rejection in the general case. **The abstraction does not normalise; it documents.** That is honest of
them, and it is the correct engineering answer for multimodal — but it means adopting BAML does not buy
provider-uniformity, it buys a different place to encode provider non-uniformity.

*The conclusion for us, and it cuts both ways.* The dimension BAML fails to normalise — multimodal content
blocks in agent journals — is a dimension **we do not have**: our decision calls are single-turn, text-only,
one system message plus one user message (`chat.rs:231-234`). So we would not pay that particular cost. But that
is also the point: BAML's abstraction value is concentrated in agent-journal, multimodal, streaming and
tool-orchestration features we neither use nor want in a decider, while the one branch it could theoretically
remove from our tree is a single `if` selecting a URL path. **Nothing is removed. A DSL, a code generator and a
dynamic library are added above an `if`.**

And BAML's own caveat is corroborating evidence for a design choice we already made: endpoint capability genuinely
differs — which is exactly why `chat.rs` carries a one-way `logprobs` latch (`:47-56`, `:300-326`) that degrades
to *no confidence* when an endpoint answers `400`, rather than assuming uniformity and fabricating a number.

### 2.6 Maturity, longevity, and the trait boundary — sizing what I am recommending against

Boundary ML: nine named people, two founders (Vaibhav Gupta, ex-Google Pixel 4 on-device depth/face-unlock and
Microsoft HoloLens; Aaron Villalpando, seven years at Amazon on EC2 internal monitoring, Prime Video and Twitch
live-streaming), 8,423 GitHub stars cited on their own page. **No funding, incorporation, revenue model or
customer list disclosed**, and BAML Cloud — the hosted observability that `@trace` targets — is "coming later
this year", i.e. the commercial model is unannounced. Credible engineers; an unpriced company.

The technical half of that, in my lane: **0.19.0 is not a patch release, it is eleven breaking changes in one
minor bump** — function specs and generated bindings redesigned (`Fn@spec()` / `Fn@stream()`), stdlib renames
(`ai.ClientSelector` → `ai.Selector`), a comparison overhaul requiring `baml.ops.Compare` / `baml.ops.Ordering`,
`all_settled` replacing `all_complete`, `WsStream` → `WebSocket`, the SAP error type changed, runtime type
bindings made "local and rigid", and the agent-journal content-block restructuring above. Posted ~8 days ago.
**No stated 1.0 commitment and no stability guarantee.** (The Rust crates version independently at 0.221.0,
which is a different numbering line and should not be read as greater maturity.)

That is a normal, healthy velocity for a pre-1.0 language and a bad property in a dependency that would sit
between our decision seams and the model. Every one of those eleven changes, landed in our tree, is a migration
on code that gates `db::delete`.

**But the right conclusion is narrower than "never".** We already own the trait boundary that this question is
really about: `DecisionProvider` (`src/decision.rs:372`), with `NullDecider` (`:402`) and `decider_or_null`
(`:436`) as the fail-closed default, and three impls behind it (`chat.rs`, `systemone.rs`, `fallback.rs`). Any
future BAML adoption belongs there — one more `impl DecisionProvider`, with `Decision<T>`, `AbstainReason` and
the confidence rules enforced on **our** side of the boundary, and SAP's repairs never reaching a caller. So the
recommendation is not "couple our prompt layer to a pre-1.0 DSL" versus "don't" — it is that the seam already
exists, it costs nothing to keep empty, and BAML has not yet earned a slot in it. That is a materially cheaper
posture than either adoption or a permanent no, and it is the one we are already in.

### 2.7 Vote — **REJECT**

**Revisit trigger, two conditions, both required:** (i) we actually adopt OTLP (H1 ships and is no longer opt-in
only), giving the comparison a subject; **and** (ii) BAML publishes a reproducible tracing methodology *and*
`baml-sys` offers a pure-source, no-download build as the default. Until both hold there is nothing here to
measure against and nothing here we can install.

### 2.8 The strongest case against my own vote

1. **I rejected a whole language partly on one crate's default feature flag.** `baml-sys` has a documented
   `no-download` feature. If it builds the engine from source, the "external code injection" objection weakens
   from structural to procedural — a ledger entry in `docs/security/build-script-vetting.md` and a pinned
   `build_dependencies` closure. I did not verify what `no-download` actually does, and I should have. That is
   the single weakest link in my BAML reasoning.
2. **I dismissed the eval framework without examining it.** `#3806` requires a calibration harness — preregistered
   held-out sets, Brier, ECE, reliability curves, null and oracle baselines, fixed-seed determinism — estimated at
   4-5 days, and `src/decision_clients/calibration.rs` (359 L) is only the start. BAML ships a built-in
   test/eval framework for exactly this class of work. If it could serve as a **development-time** harness with
   zero production dependency, "scripts are Python" is a rule about scripts, and a BAML eval file is arguably a
   script. I ruled that out on our language standard rather than on its merits.
3. **SAP might be configurable to strict.** I treated the repairing parser as a fixed property. If BAML can be
   made to hard-fail instead of coerce, the disqualifying row in §2.2 disappears and the comparison becomes a
   genuine ergonomics trade rather than an integrity one. I did not check.
4. **"We already do type-definition prompting" is a happy accident I am presenting as foresight.** Nothing in the
   tree cites the technique or pins it. A future refactor could replace that system line with a schema dump and
   no gate would notice. The honest conclusion is that BAML's post identifies a real property of our code that is
   currently *undefended* — which argues for a small pin, not for adoption, but it is a finding I owe.
5. **Pre-1.0 churn is an argument about timing, not merit, and I let it do too much work.** Eleven breaking
   changes in 0.19.0 is a reason not to adopt *now*; it is not a reason the design is wrong. A language that is
   still moving is a language still being got right. If I am honest, "wait for 1.0" and REJECT are different
   verdicts and I chose the harsher one.
6. **My provider-branching finding partly argues the other way.** I concluded BAML would relocate rather than
   remove our branching — but the reason our branching is so thin is that we only ever talk to one wire shape.
   The moment the product wants a native Anthropic or Gemini surface (better tool-use, cheaper prompt caching, a
   capability the OpenAI shim does not expose), our two-variant enum stops being elegant and starts being the
   thing BAML's content-block model exists to solve. I assessed against today's surface, which is correct for a
   GA-freeze decision and is not a permanent answer.
7. **I could not read the strongest version of their claim.** The tracing numbers have no methodology, so I
   discounted them — but "unsourced" is not "false", and a 200x Python figure, if real, would be a serious
   result for anyone instrumenting per-call. I am rejecting partly on an absence of evidence I could not close.

**What would change my mind on BAML:** a reproducible tracing benchmark with published methodology *after* we run
OTLP; a default-off download in `baml-sys`; and a demonstration that BAML can be configured to abstain rather
than repair.

---

## 3. What I could not establish

- The licence of `paw-4b-qwen3-0.6b` (the compiler), `paw-programs`, `paw-base-models`, the GGUF repos, and
  `paw-inference-logs`. No `license:` tag and no licence prose on the cards I read.
- The licence and ownership of a **generated** PAW adapter. Undefined in every source, despite `public=True`
  being the documented compile default.
- Whether `paw-rs`/`paw-candle` can expose per-label logits or grammar-constrained decoding. `run()` returns
  `String` and the crate is 21.43% documented; absence of evidence, not evidence of absence.
- What `baml-sys`'s `no-download` feature does, and whether a source build is viable.
- Whether SAP can be configured to hard-fail rather than coerce.
- Any published methodology for BAML's 6x / 200x / 1000x tracing numbers. Searched the site, the GitHub README,
  the blog and the 0.19.0 release notes; **none found**. The claim is unsourced and is excluded from my vote.
- Boundary ML's funding, incorporation and revenue model — not disclosed on their own page; BAML Cloud, the
  destination `@trace` targets, is unreleased and unpriced.
- Whether BAML's Rust crate line (0.221.0) tracks the language version (0.19.0) in any documented way.
- Whether any provider bills `response_format` as input tokens. Not verified, not asserted.
- My token figures are WordPiece from a cached MiniLM tokenizer as a proxy for a GPT BPE. Byte counts are exact.

---

## 4. Summary for the Conductor

| Project | Vote | Lands where | Displaces |
|---|---|---|---|
| PAW | **REJECT** as a dependency | `PROVIDER_LOCAL_NLI` (`src/decision_config.rs:63`, branch `f1/3806-w1abc`) — the W1d slot, already named, already validated, `grep LOCAL_NLI src/decision_boot.rs` empty | Nothing. It would *add* a second candle stack (0.11 vs our 0.10) and re-add the text parse `#3806` deletes. |
| BAML | **REJECT** | `src/decision_clients/`, behind the `DecisionProvider` trait we already own (`src/decision.rs:372`) | ~1,600-2,100 lines of `chat.rs` + `decision_clients.rs` + `fallback.rs` + parts of `decision.rs`, and with them: typed abstain, logprob-gated confidence, the `logprobs` latch, secret redaction proofs, and the `EgressClass::InferenceDecision` chokepoint. It would remove **no** provider branching — ours is one `if` choosing a URL path (`chat.rs:148-156`). |

Build W1d as the NLI cross-encoder. `src/reranker.rs` already holds a candle BERT with a classification head
(`:961-963`), an air-gapped offline weight resolver (`:1076`, `:1109`), and a degrade-never-corrupt fallback that
is honest in-band (`:990`, `capabilities.rs:359-371`). A cross-encoder's output *is* the confidence; PAW's is a
`String`. That single type difference is the whole assessment.

On BAML, the cheapest correct action is **none**, and it is already taken: `DecisionProvider` is the seam, it
costs nothing to leave a slot empty, and BAML has not earned one. Two small things are worth doing regardless of
this verdict, neither of which involves BAML: (i) pin the compact-vocabulary system prompt in
`src/decision_clients/chat.rs:213-226` with a comment saying it is deliberate — BAML's published result is
independent corroboration and the property is currently undefended against a well-meaning refactor; and (ii) fix
the `CLASSIFY_KIND_SYSTEM` 8-of-16 vocabulary drift at `src/llm.rs:841-848`, which `#3806` already names and
which is a live correctness defect on `release/v1.0.0` today, entirely independent of either subject.
