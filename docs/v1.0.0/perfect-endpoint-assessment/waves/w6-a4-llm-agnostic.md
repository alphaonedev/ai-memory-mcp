# W6-A4 — LLM / embedder vendor neutrality at ASI multi-vendor endpoints

**Lens:** §2.7 under simultaneous multi-family cognition (not “can pick one vendor”).  
**Question:** Does the substrate stay *structurally* vendor-neutral when many labs’ models operate through the same endpoint fabric at ASI scale?  
**Code anchors:** `src/llm.rs` (#1067), `AppConfig::resolve_{llm,embeddings}` (#1146/#1598), `tests/bias_displacement_invariants_2_6.rs` (I4), `src/identity/model_family.rs` (#1870), `src/curator/decorrelation_probe.rs` (#1764/#1767), `ai-memory reembed` (#1598), ROADMAP §2.7 / moonshot §2.7.  
**Ballot role:** adversarial §2.7 scorekeeper — CLAIMED config neutrality ≠ ATTESTED multi-vendor governance.

---

## VERDICT

**ACCEPT — config- and wire-layer LLM/embedder neutrality is real and load-bearing.**  
**CONDITIONAL — simultaneous multi-vendor *roles* at one endpoint are deployment topology, not a dual-slot substrate primitive.**  
**REJECT — “perfect ASI multi-vendor neutrality” while decorrelation is advisory, attestation covers ~40% of generation, and one active embedding space is process-global.**

The substrate does **not** bind writes/recall/governance to any frontier lab. It *does* bind each process to **one chat backend + one embedder + one vector space**, with optional `[llm.auto_tag]` sibling. Multi-family ASI fleets work by **composition of endpoints/agents**, not by a single daemon hosting N concurrent cognition vendors with equal structural power.

---

## CONFIDENCE

**0.84** — anchors are shippable and greppable; residual is product-topology (dual-slot roles) + attestation coverage, not “is OpenAI-compat wired.”

---

## SCORE

Held-fraction toward **perfect §2.7 under ASI multi-vendor endpoint pressure** (defaults unless noted). Not a vanity composite of all seven properties.

| Axis | Score | Reading |
|---|---:|---|
| **Config neutrality** (`AI_MEMORY_LLM_*` / `AI_MEMORY_EMBED_*` / `[llm]` / `[embeddings]`) | **0.92** | Any tier may speak any alias; tier no longer owns vendor |
| **Wire-shape coverage** (Ollama-native + OpenAI-compat) | **0.88** | 15+ aliases + `openai-compatible` escape + `vllm`; non-HTTP native APIs only via shims |
| **Recall / store path vendor-blindness** | **0.93** | I4 pin: recall blind to `AI_MEMORY_LLM_BACKEND`; source default `nhi` (#1175) |
| **Embedder neutrality + space migration** | **0.78** | API embedders shipped (#1598); one active dim/model; `reembed` is the switch tool; in-process non-HTTP trait still open (ROADMAP) |
| **Simultaneous multi-vendor roles (producer × reflector × curator)** | **0.55** | Roles are process-config slots, not dual-backend first-class; composition = multi-process / multi-agent |
| **Attested multi-family (TOFU + N≥3 write-gate)** | **0.48** default · **0.72** max-enrolled | Loader coverage hard-cap ~40%; enforce opt-in; CLAIMED metadata remains launderable when advisory |
| **Lab-capture resistance (license + no exclusive path)** | **0.90** | Apache-2.0 + trademark; no compiled single-lab sole path |
| **Narrative / DX neutrality** | **0.70** | `OllamaClient` name retained; docs still lead with Ollama default |

### Headline SCORE (this ballot)

| Claim | Score |
|---|---:|
| **§2.7 LLM-agnostic — ASI multi-vendor endpoints** | **0.79** |
| (W4 lab-capture reading of 2.7 for distance context) | **0.86** (W4-A7; do not re-litigate) |

**Delta vs W4 0.86:** −0.07 under the stricter *simultaneous multi-vendor endpoint* lens (dual-slot gap + embedder monoculture + sparse attestation), not a regression of the OpenAI-compat surface.

```
config / wire        █████████░ 0.90-ish
recall blindness     █████████░ 0.93
embed space migrate  ████████░░ 0.78
simultaneous roles   ██████░░░░ 0.55
attested multi-fam   █████░░░░░ 0.48 (default)
lab capture resist   █████████░ 0.90
§2.7 ASI multi-vend  ████████░░ 0.79
```

---

## §2.7 — property restatement (ASI multi-vendor)

**Property (moonshot / ROADMAP):** The substrate does not bind to any model family at any cognitive layer. Producer, reflector, curator, persona-synthesizer are configurable roles; the deployment fills them.

**ASI multi-vendor restatement:** At endpoints where *many* labs’ models co-author Observation/Reflection/Plan and *cross* reflect, the substrate must:

1. **Not prefer** same-vendor content in recall, ranking, or governance (substrate-side).
2. **Accept** any vendor that speaks a supported wire shape without code fork.
3. **Not freeze** the corpus to one embedding model forever (re-embed / dim honesty).
4. **Not treat** caller-CLAIMED `model_family` as diversity proof (attestation).
5. **Remain** un-acquirable into exclusive lab control without breaking §2.6.

**What v0.9 actually ships:**

| Layer | State |
|---|---|
| Chat LLM | Two providers: `Ollama` + `OpenAiCompatible`; aliases pre-fill URL/key env; fail-closed missing key |
| Embeddings | Parallel ladder; `is_api_embed_backend`; `KNOWN_EMBEDDING_DIMS` + `[embeddings].dim`; `reembed` CLI |
| Auto-tag | `[llm.auto_tag]` field-by-field fallback — **one** second model slot for structured tasks |
| Reranker | Local cross-encoder (not multi-vendor cloud); sequence/floor knobs only |
| Neutrality pins | `bias_displacement_invariants_2_6` I4; vendor-literal gate; `source=nhi` |
| Family evidence | `model_attestations` TOFU + `family_of` conservative normalizer; decorrelation probe/enforce path |

**Honest non-claims:** substrate is not an inference platform; OpenAI-compat is the lingua franca (native Anthropic Messages / vendor-private shapes are out-of-band); one process ≠ N concurrent backends with equal weight.

---

## GAPS

Ordered by ASI multi-vendor blast radius (not by LOC).

| ID | Gap | Why it bites under multi-vendor ASI | Severity |
|---|---|---|---|
| **G1** | **No dual-slot producer/reflector config** | §2.6 composition `Opus × Grok` is *deployment* (two agents/processes or sequential reconfig), not a typed dual-backend in one daemon | **High** (topology) |
| **G2** | **Single active embedding space** | Heterogeneous fleets that embed under different models poison ANN unless `reembed` + dim policy; multi-space coexistence not first-class | **High** (recall) |
| **G3** | **Attestation coverage ~40% loader cap** | Externally authored / host-LLM reflections never hit construction-boundary TOFU; N≥3 gate under-counts true diversity | **Critical** (for *attested* neutrality) |
| **G4** | **Decorrelation enforce opt-in / inert-as-default** | Multi-vendor *possibility* without multi-vendor *requirement* → monoculture theater | **Critical** for §2.6∘§2.7 |
| **G5** | **OpenAI-compat-only non-Ollama wire** | Vendors that diverge (strict native APIs, tool-call quirks) need shims; silent partial support | **Medium** |
| **G6** | **In-process non-HTTP embedder trait open** | On-device / air-gapped / custom Voyage-class in-proc still ROADMAP; API path covers most cloud | **Medium** |
| **G7** | **`OllamaClient` type name + Ollama default** | Narrative monoculture; new agents assume local-only; not a runtime couple | **Low** (DX) |
| **G8** | **Reranker single-family local model** | Autonomous tier ranking prior is one open model, not multi-vendor | **Low–Med** (ranking bias) |
| **G9** | **No runtime multi-provider failover / panel** | Endpoint resilience under vendor outage is operator HA, not substrate | **Low** (ops) |
| **G10** | **Dim-mismatch strict mode opt-in** | Mixed-corpus silent zip-truncation until `AI_MEMORY_REQUIRE_DIM_MATCH` | **Med** (vector honesty) |

**Not gaps (do not re-file as §2.7 defects):**

- MCP host being Anthropic/OpenAI/xAI — host ≠ substrate cognition boundary.  
- Operator choosing one vendor — choice is the property, not monoculture.  
- Semantic quality variance across vendors — out of TCB (capability cliff).

**Minimal close path (if productized):**

1. Typed **role slots** in config: `[roles.reflector].{backend,model,…}` independent of `[llm]` producer defaults (closes G1 without N clients on every path).  
2. Ship **embedding-space id** on rows + refuse cross-space ANN blend without reembed (G2/G10).  
3. Raise attestation emission on every substrate-invoked generate + operator_signed enrollment docs; keep CLAIMED≠ATTESTED (G3).  
4. Document **ASI multi-vendor profile**: decorrelation enforce + dim-match + distinct role keys + dual processes for producer/reflector (G4).  
5. Rename `OllamaClient` → `LlmClient` (tracked non-breaking) (G7).

---

## VOTE

| Ballot | Position |
|--------|----------|
| **On “§2.7 config/wire neutrality is shipped and real”** | **ACCEPT** (score **0.79** ASI multi-vendor; **0.86** lab-capture distance holds) |
| **On “one process is a multi-vendor ASI panel”** | **REJECT** |
| **On “embedding space is multi-vendor simultaneous”** | **REJECT** (migrate-via-reembed only) |
| **On “attested multi-family is default-enforced”** | **REJECT** |
| **On “dual-slot reflector config as next §2.7 leverage (not more aliases)”** | **ACCEPT** |
| **On “claim perfect ASI multi-vendor neutrality at endpoint”** | **REJECT** |
| **On “frontier-lab exclusive acquisition of substrate”** | **REJECT (perma)** — structural to moonshot |

**Pathway:** Treat §2.7 as **closed at the adapter boundary**, **open at the simultaneous-role + attested-diversity boundary**. Next dollar of §2.7 work is **role-slot config + embedding-space honesty + max-enrolled decorrelation profile**, not alias #16.

---

## KILLER

> *Vendor neutrality that only means “swap `AI_MEMORY_LLM_BACKEND` and restart” is **serial monoculture with a dial**, not multi-vendor governance.*  
> Under ASI, many families must co-exist on the same memory fabric **without** the substrate preferencing any family and **with** attested diversity when §2.6 is claimed. Today the dial is excellent; the **simultaneous, attested, multi-space** posture is incomplete. Shipping more OpenAI-compat aliases does not close that gap — **dual cognitive slots + embedding-space identity + enforced attested quorum** do.

---

## TOP_RISK

**Serial monoculture marketed as multi-vendor:** Operators run one backend per process, stamp CLAIMED multi-family metadata on reflections, leave decorrelation advisory, and cite §2.7 + #1067 as “we support all labs.” Auditors see config surface richness; the live fleet is one family’s priors accumulating in long-tier memory while ANN was built under one embedder. §2.6 becomes theater; §2.7 becomes a **brochure property**.

**Secondary:** Embedder switch without full `reembed` (or without dim-match) silently degrades multi-session coherence — looks like “model drift,” actually **vector-space rot**, blamed on vendors rather than substrate ops.

---

## Operator multi-vendor checklist (honest)

```
# Distinct processes/agents for producer vs reflector (topology, not magic)
AI_MEMORY_LLM_BACKEND=<family-A>     # producer process
AI_MEMORY_LLM_BACKEND=<family-B>     # reflector/curator process  (≠ A)
AI_MEMORY_EMBED_BACKEND=<one space>  # pick one; reembed on change
AI_MEMORY_REQUIRE_DIM_MATCH=1
AI_MEMORY_REFLECT_DECORRELATION_MODE=enforce
AI_MEMORY_REFLECT_DECORRELATION_QUORUM_N=3
# Enroll model_attestations (loader_observed + operator_signed)
# Never treat metadata.model_family alone as diversity proof
```

---

*W6-A4 ballot complete. SCORE §2.7 ASI multi-vendor = **0.79**. Cite ROADMAP §2.7, moonshot §2.7, #1067, #1598, #1175, #1870, #1767, `tests/bias_displacement_invariants_2_6.rs`.*
