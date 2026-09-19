# Independent assessment brief — BAML and PAW (ProgramAsWeights)

You are ONE OF THREE independent assessors. **Do not coordinate, do not read the other assessors' output, and do
not try to guess what they will say.** Divergence between the three votes is the signal the Conductor wants; three
agreeing reports written by three agents who converged on each other are worth less than one honest disagreement.

## Subjects

**1. BAML — https://boundaryml.com/ , https://github.com/BoundaryML/baml**
Established facts (verified by the Conductor, do not re-litigate, DO challenge if you find them wrong):
- Apache-2.0 licensed; Rust core; "the programming language for agents"; TypeScript-like syntax, Rust-like type
  system, typed errors, green threads, built-in testing/eval.
- The operator's interest is a specific performance claim from its site: its tracing is *"6x faster than
  OpenTelemetry in Rust, 200x faster in Python, and the traces 1000x smaller"*, and it traces every function
  rather than sampling. Note: that claim is NOT in the GitHub README and the Conductor could not find a published
  methodology. Treat an unreproduced vendor benchmark as a claim, not a measurement.

**2. PAW (ProgramAsWeights) — https://programasweights.com/ , /AGENTS.md ,
https://github.com/programasweights/programasweights-python#remote-inference-optional ,
https://arxiv.org/pdf/2607.02512 , https://huggingface.co/programasweights**
Established facts (verified by the Conductor):
- Compiles a natural-language specification into a small LoRA adapter (~22 MB) that runs **locally**; one text
  input, one text output; positioned for "regex is not enough, a full LLM is too much".
- Base models: Qwen3 0.6B (594 MB) standard, GPT-2 (134 MB) compact. Local inference by default, GPU where
  available; optional remote API (~150 ms). Context ~2048 tokens total. Compile 5-10 s, finetuned 2-5 min.
- Python SDK, a WebAssembly/browser runtime, a CLI. **No license is stated in AGENTS.md** — establishing the
  licence is part of your job, and "could not determine" is an acceptable and valuable finding.
- The operator notes there is a Rust implementation; verify that rather than assuming it.

## What you must do

1. **Establish the facts yourself.** Fetch the sources. Read the arXiv paper. Check the licence of every artefact
   we would actually depend on (repository, model weights on Hugging Face, and the adapters — weights and code can
   carry different licences, and a model card licence is not the repository licence).
2. **Cross-correlate with ai-memory using codegraph, not intuition.** The repository is at
   `/home/fate_two/v07/v09-dev`; run `codegraph explore "<symbols or question>"` there (`codegraph` is on PATH).
   Name the concrete call sites, modules and seams where each project would actually land. A cross-correlation
   without a file and a symbol in it is an opinion.
   Starting points, but find your own: the `[decision]` provider slot and its seams (#3806 — `src/decision.rs`,
   `src/decision_config.rs`, `src/decision_clients/`, `classify_kind`, `detect_contradiction`, synthesis verdicts,
   the curator merge gate); the observability surface (`decision_latency_seconds`, the `/metrics` renderer and its
   64 KiB cap, tracing/logging init); the air-gapped deployment posture (#3824/#3830 — only encrypted data in
   transit, and an air-gapped customer needs a local decider with no network).
3. **Weigh it against what we already have and what we already decided.** We have a candle runtime shipping a
   cross-encoder reranker; a decision-provider abstraction with abstain as a first-class value; a ruling that
   abstain is terminal; a rule that confidence is absent unless evidence exists; and a standard that scripts are
   Python and production components are Rust. A dependency that fights those is expensive regardless of its merits.
4. **Vote, per project, one of:** `ADOPT` (bring it into v1.0.0 or v1.1.0), `PILOT` (time-boxed experiment behind
   a seam, with the exit criteria named), `WATCH` (re-assess at a stated trigger), `REJECT` (with the reason).
5. **Argue against your own vote.** For each project, write the strongest case *against* the verdict you just
   gave, and say what evidence would change your mind. A vote with no counter-case will be discounted.

## Hard rules

- **Do not install anything, do not add a dependency, do not run their code, do not download model weights.** This
  is an assessment; nothing is to be built or vendored. Read-only.
- Never send project data, memory content or credentials to any third-party service.
- Where you cannot establish something, **say so explicitly**. "The licence of the published adapters could not be
  determined from the sources" is a finding. An assumption presented as a fact is a defect.
- Distinguish throughout between **what a vendor claims**, **what a paper measures**, and **what you verified**.
  The operator's headline numbers for BAML are a vendor claim until someone reproduces them.

## Output

Write ONE markdown file to `/ai-scratch/conductor/handoff/assess-<subject-slug>-<your-assessor-id>.md`, covering
BOTH subjects, with: a summary table of your two votes; per project — what it is, licence findings (with the
evidence), the concrete ai-memory touchpoints from codegraph, the value case, the cost and risk case, your vote,
and your counter-case. Then report the same summary back in your final message. Your assessor id is given in your
task prompt.
