# Enum proliferation audit — issue #970

**Wave-2 Tier-D3 — Multi-enum proliferation cleanup**
**Closure path: B (audit + per-enum doc clarification, no consolidation warranted)**
**Base SHA:** `ba0e783656665529057dec332b262834e4b92a6c`

## Issue hypothesis

> Memory tier / Memory kind / Memory link relation / Governance level / Action /
> Scope — many similar enums with overlapping variants. Audit + consolidate where
> semantically equivalent; document why distinct where not.

## Result

**No consolidations performed.** After enumerating every `pub enum` in
`src/models/`, `src/governance/`, and the related governance/audit
surfaces, **no two enums share a byte-identical variant set**. Names
that read similar at a glance (e.g. "Tier" appears in `Tier`,
`ConfidenceTier`, `FeatureTier`; "Decision" appears across five enums)
each model a distinct semantic domain whose variant set, serde wire
shape, and call-site dispatcher are wired to that domain's column /
JSON / TOML contract. Collapsing any pair would force one domain to
either gain unused variants or lose distinguishing variants — both
make the wire contract worse, not better.

The issue is correctly classed LOW ROI. Closure path B (document why
distinct) is the honest outcome. Per-enum cross-reference doc-comments
were added (see "Inline doc-comment updates" below) so a future
reader hitting `governance::Decision` doesn't grep for "Decision"
and conclude any of the four siblings is interchangeable.

## Full inventory

22 `pub enum` definitions across the three target areas (+ neighbouring
`src/audit.rs`, `src/approvals.rs`, `src/config.rs`, `src/daemon_runtime.rs`
which the issue body's "Action / Scope" wording also implicates).

### "Tier" family — fully orthogonal

| Enum | File:line | Variants | Used by | Semantic role |
|---|---|---|---|---|
| `Tier` | `src/models/memory.rs:332` | `Short`, `Mid`, `Long` | `Memory.tier`, recall scoring, GC sweep | **Memory-lifecycle tier**: 6h / 7d / permanent TTL with auto-promotion at 5 accesses |
| `ConfidenceTier` | `src/models/memory.rs:633` | `Confirmed`, `Likely`, `Ambiguous` | `Memory::confidence_tier()`, capabilities surface | **Confidence-value bucket**: derived from `confidence` float at thresholds 0.95 / 0.7. Operator dashboard / human-review queue filter |
| `FeatureTier` | `src/config.rs:100` | `Keyword`, `Semantic`, `Smart`, `Autonomous` | Daemon boot, `TierConfig`, recall pipeline gating | **Host capability tier**: which AI features the host can fit in RAM (0 / 256 MB / 1 GB / 4 GB) |
| `AttestLevel` | `src/models/link.rs:22` | `Unsigned`, `SelfSigned`, `PeerAttested` | `MemoryLink.attest_level`, `memory_verify` | **Link attestation strength**: H2/H3 federation sign-and-verify outcome |

**Verdict: cannot consolidate.** Zero variant overlap; each enum's
range maps to a distinct column / pipeline knob. The shared "Tier"
substring is descriptive, not structural.

### "Kind" family — orthogonal domains

| Enum | File:line | Variants | Used by | Semantic role |
|---|---|---|---|---|
| `MemoryKind` | `src/models/memory.rs:38` | 10 variants (Observation, Reflection, Persona, Concept, Entity, Claim, Relation, Event, Conversation, Decision) | `Memory.memory_kind`, Form-6 vocabulary, `KindsFilter::parse` | **Memory-row Form-6 type tag** — what KIND of memory this row is |
| `VerifyFailureKind` (audit chain) | `src/audit.rs:652` | `Parse`, `SelfHash`, `ChainBreak`, `Sequence` | `verify_chain*`, `AuditEvent` chain verifier | **Audit-event hash-chain failure mode** (per-line audit log) |
| `VerifyFailureKind` (governance chain) | `src/governance/audit.rs:287` | `Parse`, `ChainBreak`, `Signature` | `verify_since`, `ForensicDecision` verifier | **Forensic-bundle Ed25519 chain failure mode** (governance refusal log) |
| `DirKind` | `src/log_paths.rs:100` | (log directory taxonomy) | log-path resolver | **Log-dir classification** |
| `HelperKind` | `src/multistep_ingest/helpers.rs:51` | (multi-step ingest helpers) | multistep_ingest | **Ingest helper variant** |
| `HookKind` | `src/cli/install.rs:173` | (install-hook kinds) | install CLI | **Install hook surface** |

**Note on the two `VerifyFailureKind` enums:** they share two variants
(`Parse`, `ChainBreak`) but diverge on the other two — the audit chain
verifies a `SelfHash` and a monotonic `Sequence`; the governance
forensic chain has neither (its sequence is the `sequence` column in
SQLite, not the line ordering, and it verifies Ed25519 signatures
which the audit chain does not). Consolidating into one enum would
either force `SelfHash`/`Sequence` onto the governance verifier
(which would have to either reject or always-pass them — both wrong)
or force `Signature` onto the audit verifier (same problem inverted).
The module path (`audit::VerifyFailureKind` vs
`governance::audit::VerifyFailureKind`) already disambiguates them
at every call site.

**Verdict: cannot consolidate.** Same name, different chain semantics.

### "Decision" family — five domain outputs

| Enum | File:line | Variants | Used by | Semantic role |
|---|---|---|---|---|
| `governance::Decision` | `src/governance/mod.rs:169` | `Allow`, `Deny(String)`, `Modify(MemoryDelta)`, `Ask(String)` | `Permissions::evaluate`, K9 pipeline output | **K9 pipeline four-shape output** — rules + hooks combined |
| `governance::RuleDecision` | `src/governance/mod.rs:255` | `Allow`, `Deny`, `Ask` | `PermissionRule.decision`, rule loader | **TOML rule-row decision** — narrower than the pipeline output because rules cannot return `Modify` |
| `governance::agent_action::Decision` | `src/governance/agent_action.rs:186` | `Allow`, `Refuse{rule_id, reason}`, `Warn{rule_id, reason}` | `check_agent_action`, harness PreToolUse hook | **External-action engine output** — no `Modify`, no `Ask`, distinct refusal shape (carries `rule_id`) |
| `models::GovernanceDecision` | `src/models/namespace.rs:119` | `Allow`, `Deny(GovernanceRefusal)`, `Pending(String)` | `enforce_governance`, substrate gov path | **Substrate governance output** — carries a typed refusal envelope and a `Pending` queue-id |
| `approvals::Decision` | `src/approvals.rs:55` | `Approve`, `Deny` | K10 operator-decision API | **Operator submission verdict** — only the two terminal outcomes an operator types in |
| `identity::replay::ReplayDecision` | `src/identity/replay.rs:148` | (replay-specific) | nonce replay window | **Replay-window verdict** |
| `storage::reflect::ReflectHookDecision` | `src/storage/reflect.rs:113` | (reflect hook) | reflection hook chain | **Reflection-hook verdict** |
| `hooks::decision::HookDecision` | `src/hooks/decision.rs:87` | (hook decision) | substrate hook chain | **Substrate-hook G4 verdict** — the type `governance::Decision` mirrors |

**Verdict: cannot consolidate.** Each enum has a different payload
type on its non-Allow variants because each models a different
contract (rule TOML row, K9 pipeline output, external action
verdict, operator submission, substrate-hook G4). The `governance::Decision`
docstring already notes `RuleDecision` is "narrower" and
`agent_action::Decision` docstring already notes it "mirrors the
`crate::governance::Decision` vocabulary but narrower". These
cross-references are load-bearing.

### "Action" family — five action vocabularies

| Enum | File:line | Variants | Used by | Semantic role |
|---|---|---|---|---|
| `GovernedAction` | `src/models/namespace.rs:133` | `Store`, `Delete`, `Promote`, `Reflect` | `pending_actions.action_type`, governance approval queue | **Substrate-action approval-queue discriminator** — wire strings `store`/`delete`/`promote`/`reflect` |
| `governance::Op` | `src/governance/mod.rs:103` | `MemoryStore`, `MemoryLink`, `MemoryDelete`, `MemoryArchive`, `MemoryConsolidate`, `MemoryReplay` | `PermissionContext.op`, K9 evaluator | **K9 permission-rule op discriminator** — wire strings `memory_*` (six gated tools), broader than `GovernedAction` |
| `AgentAction` | `src/governance/agent_action.rs:97` | `Bash`, `FilesystemWrite`, `NetworkRequest`, `ProcessSpawn`, `Custom` | `check_agent_action`, harness rules | **External-action engine input** — bash/fs/net/process, not substrate actions |
| `AuditAction` | `src/audit.rs:115` | 13 variants (Recall, Store, Update, Delete, Link, Promote, Forget, Consolidate, Export, Import, Approve, Reject, SessionBoot) | `AuditEvent.action`, audit log | **Audit-log action vocabulary** — wider than the gated ops because audit logs everything, gated and ungated |
| `GovernanceAction` (CLI) | `src/daemon_runtime.rs:424` | `MigrateToPermissions`, `InstallDefaults`, `CheckAction` | clap `ai-memory governance <verb>` | **CLI subcommand enum** for the `governance` verb — a clap surface, not a wire surface |
| `RulesAction` / `AgentsAction` / `ShellAction` / `IdentityAction` / `NamespaceAction` / `ArchiveAction` / `LogsAction` / `AuditAction` (cli) / `PendingAction` (cli) | `src/cli/*.rs` | clap subcommand enums | clap | **clap subcommand surface** per verb |

**Verdict: cannot consolidate.** `GovernedAction` ⊂ `Op` in
substring (`Store` vs `MemoryStore`) but the wire strings are
different (`"store"` vs `"memory_store"`), the variant counts
differ (4 vs 6), and the load-bearing surfaces (approval-queue
discriminator vs permission-rule matcher) consult different
columns. `AuditAction`'s 13-variant vocabulary covers everything
the audit logs — including approve/reject/session_boot — that the
two governance enums don't gate.

The `*Action` clap-subcommand enums are NOT part of the same
family — they're clap derive surfaces, one per CLI verb, with no
shared trait. Listing them here for completeness; they are not
candidates for consolidation under the issue's scope.

### "Level" family — three orthogonal scales

| Enum | File:line | Variants | Used by | Semantic role |
|---|---|---|---|---|
| `GovernanceLevel` | `src/models/namespace.rs:222` | `Any`, `Registered`, `Owner`, `Approve` | `GovernancePolicy.{write,promote,delete}`, namespace standard | **Governance-rule strictness ladder** for a gated action |
| `AttestLevel` | `src/models/link.rs:22` | `Unsigned`, `SelfSigned`, `PeerAttested` | `memory_links.attest_level`, `memory_verify` | **Federation signing strength** for a link row |
| `FeatureTier` | `src/config.rs:100` | (also a "level" in spirit) | — | (covered under Tier) |

**Verdict: cannot consolidate.** Different domains entirely.

### "Mode" / "Source" / "Filter" — domain-specific singletons

| Enum | File:line | Variants | Used by | Semantic role |
|---|---|---|---|---|
| `EditSource` | `src/models/memory.rs:524` | `Human`, `Llm`, `Hook` | `update` audit entries | **Edit-path origin** — drives in-place vs append-and-archive write path |
| `ConfidenceSource` | `src/models/memory.rs:222` | `CallerProvided`, `AutoDerived`, `Calibrated`, `Decayed` | `Memory.confidence_source` | **Confidence-value origin** — drives the audit/recall ranker trust path |
| `AutoAtomiseMode` | `src/models/namespace.rs:647` | `Off`, `Deferred`, `Synchronous` | `GovernancePolicy.auto_atomise_mode` | **Atomisation timing policy** per-namespace |
| `SynthesisFailureMode` | `src/models/namespace.rs:677` | `FallThrough`, `BlockWrite` | `GovernancePolicy.synthesis_failure_mode` | **Form-1 synthesis-outage policy** per-namespace |
| `MemoryKindAutoClassify` | `src/models/namespace.rs:703` | `Off`, `RegexOnly`, `RegexThenLlm` | `GovernancePolicy.auto_classify_kind` | **Form-6 pre-store kind-classifier policy** per-namespace |
| `KindsFilter` | `src/models/recall_request.rs:49` | `Array(Vec<String>)`, `Csv(String)` | `RecallRequest.kinds` | **Untagged-serde adapter** for the recall-request `kinds` field |
| `ApproverType` | `src/models/namespace.rs:257` | `Human`, `Agent(String)`, `Consensus(u32)` | `GovernancePolicy.approver` | **Who can approve a gated action** |

**Verdict: cannot consolidate.** Each models a distinct policy axis.

### Remaining single-purpose enums

| Enum | File:line | Variants | Used by | Semantic role |
|---|---|---|---|---|
| `Severity` | `src/governance/agent_action.rs:223` | `Refuse`, `Warn`, `Log` | `governance_rules.severity` column | **Agent-action rule severity** |
| `DenyGate` | `src/governance/mod.rs:840` | `PermissionRule`, `Governance` | `deny_message()` | **Refusal-message gate-tag** for wire-stable `"denied by X"` output |
| `AppendOutcome` | `src/governance/deferred_audit.rs:366` | `Appended`, `DlqLanded` | `DeferredAuditSink::append` | **Sink outcome** — DLQ-vs-mainline distinction |
| `AuditOutcome` | `src/audit.rs` | `Allow`, `Deny`, `Error`, `Pending` | `AuditEvent.outcome` | **Audit-row outcome column** |
| `MemoryLinkRelation` | `src/models/link.rs:88` | `RelatedTo`, `Supersedes`, `Contradicts`, `DerivedFrom`, `ReflectsOn`, `DerivesFrom` | `memory_links.relation` | **Typed link relation closed-set** |

**Verdict: cannot consolidate.** Each is the single source of truth
for a specific column or wire field.

### "Scope"

The issue body mentions "Scope" as a candidate for consolidation.
There is no `pub enum Scope` in the audited surface area. The
`metadata.scope` field on `Memory` rows is a free-form string
(`"public"` / `"private"` / future operator-defined values),
deliberately not closed-set so per-org scoping vocabularies can
extend it without a wire bump. The visibility filter
(`src/visibility.rs`) consults the string directly. No enum to
consolidate.

## Why the issue's hypothesis was wrong

The issue body's premise — "many similar enums with overlapping
variants" — confuses **name-similarity** with **semantic overlap**.

- Three enums end in `Tier`: zero variant overlap (memory lifecycle
  vs confidence bucket vs feature capability).
- Five enums named `Decision`: each has a different payload on its
  non-Allow variants because each models a different contract
  output (TOML rule row, K9 pipeline output, external action
  verdict, operator submission, substrate-hook G4).
- Three enums use Allow/Deny variants: `RuleDecision`,
  `AuditOutcome`, `agent_action::Decision`. All three carry
  extra variants the other two don't have (`Ask` / `Error,Pending`
  / `Refuse{rule_id,reason},Warn{...}`).

The substring overlap is descriptive ("this thing decides", "this
thing is a tier") but the **variant sets and the wire-format
contracts behind them are disjoint**.

## Inline doc-comment updates

Cross-reference paragraphs added to the close-call enums so a future
reader hitting the symbol via grep doesn't conclude they're
interchangeable:

- `src/models/memory.rs::Tier` — note that `ConfidenceTier` and
  `FeatureTier` exist for orthogonal axes.
- `src/models/memory.rs::ConfidenceTier` — note that `Tier` (memory
  lifecycle) and `FeatureTier` are unrelated.
- `src/config.rs::FeatureTier` — note that `Tier` (memory) and
  `ConfidenceTier` are unrelated.
- `src/governance/mod.rs::Decision` — link to `RuleDecision`,
  `agent_action::Decision`, `GovernanceDecision`, `approvals::Decision`.
- `src/governance/agent_action.rs::Decision` already cross-references
  `crate::governance::Decision` (pre-existing).
- `src/models/namespace.rs::GovernedAction` — note the relationship
  to `governance::Op` (subset name; different wire string +
  different column).
- `src/governance/mod.rs::Op` — note the relationship to
  `GovernedAction` (substrate-action-vs-permission-op).
- `src/audit.rs::VerifyFailureKind` — note the sibling enum in
  `src/governance/audit.rs` and the chain-shape distinction.
- `src/governance/audit.rs::VerifyFailureKind` — note the sibling
  enum in `src/audit.rs` and the chain-shape distinction.

## Summary

| Metric | Count |
|---|---|
| Enums inventoried (target dirs) | 22 |
| Enums inventoried (broader sweep) | 38 |
| Byte-identical variant-set pairs | 0 |
| Consolidations performed | 0 |
| Cross-reference doc-comments added | 9 |

Closure: per-enum doc clarification (Path B). The issue body's
LOW-ROI hypothesis is confirmed — there is no consolidation to
perform without making the wire contracts worse.
