# BAML (BoundaryML) — 1x3 adversarial assessment and adjudication

**Adjudicator:** Claude Opus 5 (Conductor, ai-memory v1.0.0 GA epic)
**Date:** 2026-09-19
**Tracking issue:** #3841 (this document), #3842 (PAW, the sibling assessment)
**Tree assessed:** `/mnt/t9/v07/v09-dev` @ `8b4f65a22`, with branch claims against
`origin/release/v1.0.0` @ `ec1b61c43` and `origin/f1/3806-w1abc` @ `271279072`.
**Evidence:** `docs/reviews/opus5-1x3-baml-paw-20260919-evidence/` — the three
assessor reports verbatim, plus the brief exactly as issued.

---

## 1. Ruling

**REJECT for v1.0.0 and v1.1.0 — as a dependency.**
**One component is worth taking, and it does not require the dependency.**

| Assessor | Emphasis | Vote |
|---|---|---|
| A | Licensing and supply chain | WATCH |
| B | Technical fit against our own seams | REJECT |
| C | Adversarial | REJECT |

Two reject, one watch. No assessor voted to adopt or to pilot. The dissent is
the weaker form of the same conclusion, not a counter-position: A's WATCH is
explicitly conditioned on the runtime dylib download being resolved, which is
the same defect B and C rejected on.

The adjudicated disposition is REJECT rather than WATCH because of freeze, not
because of a technical disagreement. BAML closes no GA blocker. It is a
feature, and the freeze admits defects in scope, regressions, and exactly one
operator-admitted feature (#3806, already spent). Detail in §6.

---

## 2. Method, and why it was run three ways

The three assessors were given one shared brief, three different emphases, and
an explicit instruction not to coordinate. Each was required to reach a vote and
to write the strongest counter-case against its own vote. None read another's
report. The scheme exists because a single reviewer of a vendor claim tends to
assess the claim as presented; three reviewers with different incentives assess
the thing.

It earned its cost here. Three independent lines of work converged on the same
three findings, and two assessors independently caught the same two factual
errors in the brief I wrote. Convergence from non-communicating reviewers is
evidence; agreement from reviewers who talked is not.

---

## 3. What was actually established

### 3.1 The licence is genuinely clean, and is not the problem

Root `LICENSE` and `engine/LICENSE` are both stock, unmodified Apache-2.0, with
no Elastic or Business Source carve-out for the engine. Every crate in the
family — `baml`, `baml-sys`, `baml-macros`, `baml-cli`, `baml_bridge` — resolves
to Apache-2.0 on crates.io, owned by the founder's account rather than a
squatter. There is no contributor licence agreement, so the grants on published
versions are irrevocable and a fork is legally viable.

That is compatible with our own Apache-2.0 posture. The licence would not have
stopped us. Something else did.

One corner stays open and is recorded as open rather than resolved: the
per-file licences under `engine/vendored/` were not enumerated, and Boundary's
hosted terms and pricing could not be located as published documents.

### 3.2 The headline claim is unsourced — traced to a marketing string

The claim that motivated this assessment is that BAML's tracing is six times
faster than OpenTelemetry in Rust, two hundred times faster in Python, with
traces a thousand times smaller.

All three assessors went looking for the methodology. None found one. The
claim is absent from the README, from the documentation index, from the pricing
page, from the 0.18.0 notes and from the 0.19.0 notes. Assessor C located the
claim's only home in the repository: a string inside a marketing page's section
array, whose "read more" link resolves to a generic documentation landing page.
A code search for OpenTelemetry across the repository returns six files — a
vendored README, that marketing page, a React component, a Go module file and
two lockfiles. There is no benchmark code.

The one benchmark that does exist measures something else and says so: its
stated metric is BAML's own profiler on versus off, not BAML against
OpenTelemetry. Boundary's own podcast gives the trace-size mechanism as roughly
100 bytes to 800 bytes, which is eight times, against a headline of a thousand.

Assessor C also identified the parameter the claim omits, which is the one that
decides it. "A thousand times smaller, on every function instead of sampling"
partially cancels: at one percent head sampling the net is ten times; at a
tenth of a percent it is break-even. The claim never states a sampling rate.

**Recorded as unsubstantiated.** Not disproven — unsubstantiated, which is a
different and more precise thing. No assessor's vote rests on it.

### 3.3 The Rust path downloads and executes an unverified native binary

This is the finding that decides the engineering question, and A and C reached
it independently.

`baml-sys` declares `default = ["download"]`. Its documented library-resolution
order ends in "from GitHub releases, if the download feature is enabled". Its
runtime dependencies include a dynamic loader and an HTTP client. So adding
BAML to a manifest with default features yields a crate that reaches the public
internet *at runtime* and loads a native shared object it has just fetched.

Assessor C found the newer bridge states its own integrity posture out loud in
the loader source: a missing sidecar is a warning, not a failure. That is
fail-open verification on code execution.

Three consequences land specifically on this repository:

- **It is an egress lane our taxonomy does not have.** `src/egress.rs` enumerates
  five classes and its own doc comment asserts the taxonomy is complete. A
  dylib fetch is a sixth, ungoverned by the inference-egress evaluator and
  invisible to the signed refusal row. Our egress resolver deliberately fails
  closed on a *typo*. This path would not fail closed at all.
- **It defeats the bill of materials.** Our release workflow documents the
  CycloneDX SBOM as enumerating every resolved dependency in the lockfile. A
  binary acquired at runtime appears in no lockfile and therefore in no SBOM.
  The largest single unit of executable code in the integration would be the
  one unit the bill of materials does not mention.
- **It is a plan we already killed, with a downloader attached.** Our own
  manifest records the ruling on `vectorlite`: a native library with no Rust
  crate cannot be acquired reproducibly across our CI matrix and release
  channels. Disabling the downloader returns us to exactly that unsolved
  problem across six platform targets.

Against the freeze's encryption and air-gap standards (#3824, and posture 2 in
the #3806 requirements) this is disqualifying on its own. An air-gapped
customer's process would still attempt the fetch.

### 3.4 Their failure mode is the inversion of ours

Assessor B put this most sharply, and it is the deepest objection in the set.

BAML's schema-aligned parser *repairs* malformed model output. We *abstain* on
it. Those are opposite answers to the same question, and the question is asked
at a seam that can delete data.

B traced our path: unusable output reaches `read_structured_answer`, returns
none, and becomes an abstain. So BAML's improvement — six percent malformation
to zero on their benchmark — buys us availability, not integrity. Availability
is tradeable. The abstain is the constraint. A dependency whose core value
proposition is to convert our constraint into our tradeable is not a good fit
at this seam regardless of how well it is engineered.

### 3.5 The token-reduction case does not survive measurement against our tree

Assessor B measured it rather than accepting it. Our `response_format` schema
for the sixteen-way classification is 375 bytes; our system line is 327 bytes
and 72 proxy tokens, against 285 bytes and 121 tokens for the inlined JSON
Schema that BAML argues against. A BAML-style TypeScript rendering measured 232
bytes and 74 tokens.

We already send the compact form, and ours is shorter in tokens than the
schema. There is no win available.

Their benchmark also does not reach us. It is Llama 2 7B with schema-in-prompt
via Instructor, and they state they did not test native structured output. We
send strict JSON schema with the closed vocabulary as an enum, temperature
zero, a fixed seed, and we read logprobs. Assessor C's statistical read: Fisher's
exact two-sided p of 0.029 on six-of-hundred versus zero-of-hundred, but the
Wilson intervals overlap, on one task, on one model, with no seeds or code
published.

### 3.6 The abstraction leaks, by their own documentation

BAML 0.19.0 restructures message content into typed blocks and notes that
provider support differs across Gemini, Anthropic and OpenAI. That documents
non-uniformity rather than normalising it. Assessor B measured our side: our
provider enum has two variants covering seventeen-plus vendors, and the
decision path has a single conditional choosing a URL path. We would pay the
integration cost and still write provider-conditional code.

### 3.7 Stability: every minor bump is a refactor

Assessor A quantified it: roughly nineteen breaking changes across 0.18.0 and
0.19.0, shipped fifteen days apart, including more than thirty type renames,
outright deletions, removal of Jinja templating, and exception-type changes.
0.19.0 renamed the standard library nine days before 0.20.0. The stable Rust
crate has been stale since April; the new bridge is nightly-only.

### 3.8 Vendor viability and the monetisation surface

Nine people, about seven engineers, no disclosed funding, investors, or revenue
model on the team page. Assessor C found the legal entity named in the site's
own structured data as Gloo Chat, Inc. Assessor A confirmed from Boundary's own
pricing page that **observability is the forthcoming paid Cloud product**, gated
on an API key, with no OTLP export.

That closes the loop on the original question. The capability the operator
asked about is the paid tier. Apache-2.0 covers the compiler, not the
collector. And in an acquisition scenario, the runtime dylib download stops
being a hygiene problem and becomes an acquirer-controlled code channel into
our runtime.

---

## 4. The strongest case for BAML, which is real

All three assessors were required to make it, and all three found the same
thing.

`engine/baml-lib/jsonish` is a mature, Apache-2.0, **pure-Rust**, error-tolerant
JSON parser. It is better than our hand-rolled `extract_json_object` in
`src/synthesis/mod.rs`. It is vendorable under a licence we already comply with,
**without adopting the language, the DSL, the compiler, the VM, the nightly
bridge, or the dylib downloader.**

Taking a well-tested parser under a permissive licence is a different decision
from taking a dependency on a pre-1.0 vendor, and it should be evaluated on its
own terms.

**Disposition:** deferred to v1.1.0 as a candidate, not admitted to v1.0.0. It
is an improvement, not a defect fix, and the freeze does not admit it. Filed as
a follow-up on #3841. Note the caution that comes with it: a tolerant parser is
an availability improvement, and we must not let it silently repair output that
our abstain path should have refused. Any adoption has to keep the abstain.

Separately, **type-definition prompting is free to take and requires no
dependency at all.** No patent is claimed, the code is Apache-2.0, and there is
heavy prior art including Microsoft's TypeChat. Assessor A's finding is that
the idea is fully separable from the product; assessor B and C's finding is
that we already do the equivalent or better. Nothing to adopt, nothing owed.

---

## 5. Corrections to the brief I issued

Two assessors independently caught the same two errors in my own brief. I am
recording them because an instrument that misstates the tree is worse than one
that says nothing (rule mm), and because the brief is published alongside this
document.

1. **The #3806 `[decision]` files are not on the release branch.** There is no
   `src/decision.rs`, `src/decision_config.rs` or `src/decision_clients/` at
   `origin/release/v1.0.0`. They exist on unmerged `origin/f1/3806-w1abc` @
   `271279072`. At the release commit the slot is a ruling, not code. I wrote
   the brief as though the code had landed.
2. **There is no 64 KiB cap on the metrics renderer.** `metrics::render()` is
   unbounded. The 64-kilobyte literals I was thinking of are request-body read
   limits elsewhere.

A third correction is to the operator's premise as I relayed it, and it applies
to both assessments: the PAW Rust crates are not PAW's. See #3842.

---

## 6. Freeze disposition

125 open GA blockers at the time of assessment. BAML closes none of them. It is
a feature, and the freeze rule admits a defect in something in scope, or a
regression, and otherwise requires that admitting anything be paid for with a
publicly stated customer cost. #3806 is on record as the one feature admitted
since the freeze, by operator order, and that exception is spent.

A pilot would land in `src/synthesis/mod.rs` or `src/decision_clients/`, both
mid-chain right now. There is no version of this that is cheap this week.

**v1.0.0: rejected. v1.1.0: rejected as a dependency; the `jsonish` parser
carried forward as a separate, self-contained candidate.**

Conditions under which I would reopen the dependency question, stated in
advance so the answer is not a matter of taste later:

- A published tracing methodology that states its sampling rate.
- A stable Rust crate with no runtime download, on stable Rust.
- A 1.0 stability policy.

---

## 7. Cross-correlation with ai-memory memory

The prior decisions this assessment is consistent with, recorded in the
`global` namespace: the `vectorlite` acquisition ruling (#1860), the no-hardcoded-
vendor-name rule in control paths (#3806 requirements §1), the egress taxonomy
completeness assertion in `src/egress.rs`, the default-OFF OTLP posture recorded
in our logging documentation, and the 2026-09-19 encryption-in-transit standard
(#3824), whose air-gap posture the dylib download cannot satisfy.

One open item for tracking, surfaced during this assessment and **not** part of
the BAML ruling: Boundary published a post on 2026-09-17 announcing TypeSafe
AI's Jev model as a BAML v1 client. That is relevant to our own Jev work in
freeze and is recorded on #3806, not here.

---

## 8. A gap this assessment exposed in our own controls

There is no `deny.toml` and no `cargo-deny` licence gate in this repository.
The licence half of our supply-chain control is currently a human reading a web
page, which is literally what this assessment was. A licence allow-list would
have answered the BAML half mechanically, and would have hard-blocked PAW's
unlicensed artefacts at the door without anyone reading anything.

Filed as a follow-up. It is the most valuable thing this assessment produced,
and it is about us rather than about either vendor.
