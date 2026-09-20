# PAW (ProgramAsWeights) — 1x3 adversarial assessment and adjudication

**Adjudicator:** Claude Opus 5 (Conductor, ai-memory v1.0.0 GA epic)
**Date:** 2026-09-19
**Tracking issue:** #3842 (this document), #3841 (BAML, the sibling assessment)
**Tree assessed:** `/mnt/t9/v07/v09-dev` @ `8b4f65a22`, with branch claims against
`origin/release/v1.0.0` @ `ec1b61c43` and `origin/f1/3806-w1abc` @ `271279072`.
**Evidence:** `docs/reviews/opus5-1x3-baml-paw-20260919-evidence/` — the three
assessor reports verbatim, plus the brief exactly as issued.

---

## 1. Ruling

**REJECT, unanimously, for v1.0.0 and v1.1.0.**

| Assessor | Emphasis | Vote |
|---|---|---|
| A | Licensing and supply chain | REJECT |
| B | Technical fit against our own seams | REJECT |
| C | Adversarial | REJECT |

Three independent rejections on three different grounds, any one of which is
sufficient on its own:

1. **No licence exists on any weight we would depend on.** No grant means all
   rights reserved.
2. **The output type is a string.** Our slot's output type is a decision with an
   optional calibrated confidence. Adopting PAW re-adds the text parse that
   #3806 exists to delete.
3. **The Rust implementation is not theirs**, and the artefact cannot be
   operator-pinned or signed, which our attested-weights path requires.

The licence finding is dispositive and nothing else needs to be weighed until
it changes. I am recording the rest anyway, because the thesis is interesting
and the operator should know why an interesting thesis still loses.

---

## 2. What PAW claims

PAW compiles a natural-language specification into a small LoRA adapter — a
"neural binary" of roughly 22 megabytes — over a small base model, Qwen3 0.6B or
GPT-2. One text in, one text out. The pitch is that a 0.6B model carrying a
compiled program matches a 32B model prompted conventionally.

The thesis is not silly. It is, in fact, approximately the thesis of our own
W1d work. That turns out to be the most useful thing about it (§5).

---

## 3. The licence finding

Assessors A and C established this independently, and C verified it through the
Hugging Face API rather than by reading a page.

- The Python SDK is MIT. All eleven repositories in the GitHub organisation are
  MIT. The paper is CC BY 4.0, which covers the paper text.
- **All seven published model repositories and the dataset carry no licence
  field at all.** That includes the compiler, the base-model bundle, and the
  adapter repository carrying 433-plus variants and, by C's measurement, 66,973
  downloads. C confirmed the licence field is null on every one.

The base models themselves are clean — Qwen3-0.6B Apache-2.0, GPT-2 MIT,
Qwen3-4B-Instruct Apache-2.0 — which makes the omission worse rather than
better. The base-model bundle redistributes a Qwen3 artefact with no licence,
no notice file and no attribution, which is an apparent upstream Apache-2.0
compliance defect that we would inherit by depending on it.

No terms of service, no privacy policy and no retention statement could be
located for the hosted API.

**No grant means all rights reserved.** For a product shipping to enterprise
and government customers under an Apache-2.0 posture with a published bill of
materials, this is the end of the analysis.

It is also, as assessor A fairly notes in its counter-case, fixable by one
email. A licence file is a missing YAML line, not a design flaw. That is why §7
states the precondition for reconsidering rather than closing the door.

---

## 4. Why it would still lose with a licence

### 4.1 The output type is wrong for our seam

Assessor B's finding, and the cleanest technical objection in the set.

PAW's entire Rust inference surface is a function from a string to a string.
Our decision slot's output type is a decision carrying an optional validated
confidence. #3806 exists precisely to delete a text parse from a seam that can
delete data. Adopting PAW would re-add it.

### 4.2 It cannot be honest about uncertainty

Assessor C's finding, and the one that would worry me most if the licence were
fixed tomorrow.

PAW is text in, text out, with no logprobs on any surface. Under our rule that
confidence comes from logprobs, every PAW answer carries no confidence, forever.

Worse: a causal language model always emits a token, so it cannot decline. Its
abstain rate equals its malformation rate, not its uncertainty rate. The
failure mode that follows is the dangerous one — answers that are subtly wrong,
well-formed, and inside the expected vocabulary pass straight through as a
clean verdict from the decision model. An abstain path that can only catch
malformed output is not an abstain path.

The paper concedes the artefact is opaque, calling inspection and debugging of
neural binaries an open direction.

### 4.3 It cannot satisfy our attested-weights path

Assessor A found the structural killer. Our attested-weights verification
refuses to serve on a hash mismatch and fails closed on a signature with no
operator key (#654). An adapter synthesised at runtime by a generative model
cannot be operator-pinned or signed. The two designs are incompatible at the
level of what a weight *is*.

### 4.4 The compile step is hosted, and the logs are public

`paw-inference-logs` is a public Hugging Face dataset of 3,773 rows of hosted-API
user inputs and outputs, with no policy anywhere stating that it will not
continue. Compilation is hosted and the documented default is public.

A specification sent for compilation is off-host data. Under #3824 and the
air-gapped posture, that closes the remote path permanently and independently of
everything above.

### 4.5 The Rust implementation is not theirs — correcting our own premise

All three assessors caught this, and it corrects the brief I issued.

The PAW organisation has eleven repositories and **zero Rust**. The crates
(`paw-rs`, `paw-core`, `paw-candle`, `paw-llamacpp`) come from an unaffiliated
author whose own README marks the project unofficial. Two stars, one
contributor, dormant since July, with the entire commit history spanning four
days.

Adopting it would also mean a second, incompatible inference stack: candle 0.11
against our 0.10, and hf-hub 1.0 against our 0.5. Both pairs are
semver-incompatible, so both would compile into the binary simultaneously.

### 4.6 Its own benchmark table does not support the pitch

Assessor C read the paper's table rather than the abstract. PAW **loses to
Qwen3-32B on all four external benchmarks** — by 3.2, 8.3, 2.3 and 4.0 points —
and wins only on the benchmark its own compiler was trained on. On that one, a
contained and properly licensed 20B model beats it by 11.7 points.

---

## 5. The strongest case for PAW, which is real and which we have already built

Required of every assessor, and worth stating plainly because it is the most
interesting output of this assessment.

**PAW's thesis is correct, and it is what our own `local-nli` work already
does.** A small, contained, special-purpose model beats a large general one at a
narrow decision task. Assessor B found the seam already cut on
`origin/f1/3806-w1abc`: the canonical selector for the in-process NLI
cross-encoder decision provider, documented as opening no socket and carrying no
credential, with validation that hard-fails if a base URL or API key is supplied
alongside it.

"Opens no socket" is load-bearing in a way that is easy to miss. #3824 encrypts
loopback. An in-process decider is the only design that sits structurally
outside that requirement rather than having to satisfy it.

And we already ship the runtime. Our reranker holds classifier weights on a
candle BERT, with an air-gapped offline weight resolver and an honest in-band
degrade path. A cross-encoder's native output *is* a number, which is exactly
the property PAW lacks.

So the right reading of PAW is not "a dependency we declined". It is
independent confirmation that the W1d design is pointed the right way — and a
demonstration of what it would have cost us to reach the same idea through a
hosted compiler, an unlicensed artefact and a text parse.

---

## 6. Corrections to the brief I issued

Recorded because the brief is published alongside this document and because a
false premise in an instrument is worse than a missing one.

1. **The Rust crates are not PAW's.** I relayed them as the project's own. They
   are an unaffiliated author's unofficial SDK. All three assessors corrected
   this independently.
2. **The #3806 `[decision]` files are not on the release branch.** They are on
   unmerged `origin/f1/3806-w1abc`. See #3841 §5.
3. **There is no 64 KiB cap on the metrics renderer.** See #3841 §5.

---

## 7. Freeze disposition, and the precondition for reconsidering

PAW closes no GA blocker. It is a feature. The freeze admits defects in scope,
regressions, and one operator-admitted feature which is already spent on #3806.

**v1.0.0: rejected. v1.1.0: rejected.**

The precondition for reconsidering is the licence, and nothing else matters
until it is met. Stated concretely so the bar is not a matter of taste later:

- An explicit licence on the compiler weights, the base-model bundle and the
  generated adapters.
- Offline compilation, so a specification never leaves the host.
- Operator-pinned and operator-signed adapters, satisfying #654.

If all three were met, the honest-confidence objection in §4.2 would still
stand and would still, in my judgement, be decisive for a seam that can delete
data. I would move from reject to watch, not to pilot.

---

## 8. Cross-correlation with ai-memory memory

Consistent with: the attested-weights refusal path (#654); the air-gapped
offline weight resolver already shipped in the reranker; the 2026-09-19
encryption-in-transit standard (#3824) and its three use cases, under which a
hosted compile step is third-party egress; the #3806 ruling that the decision
slot returns a typed decision rather than parsed text; and the freeze rule
itself.

The follow-up filed against both assessments — adding `deny.toml` and a
`cargo-deny` licence gate — would have hard-blocked PAW's unlicensed artefacts
mechanically, without a human reading a model card. That is the durable lesson
here, and it is about our controls rather than about PAW.
