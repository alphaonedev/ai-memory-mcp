// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::default_metadata;

// Canonical `MemoryKind` spellings duplicated across `as_str` / `from_str`
// (#1558 batch 6).
const KIND_OBSERVATION: &str = "observation";
const KIND_REFLECTION: &str = "reflection";
// v1.0.0 epistemic-typing vocab (#1945, spec §4 ship-now half). Named
// consts (never scattered literals) so the vendor / hardcoded-literal
// gates have a single definition site — the KIND_OBSERVATION precedent.
const KIND_TOLD: &str = "told";
const KIND_INSTRUCTION: &str = "instruction";
const KIND_INTERVENTION: &str = "intervention";
// v1.0.0 `kind_provenance` closed vocab (#1945, spec §4). Unsigned
// metadata recording HOW the kind was assigned — the ConfidenceSource
// precedent. Single-definition-site consts for the literal gates.
const KIND_PROVENANCE_DECLARED: &str = "declared";
const KIND_PROVENANCE_CHANNEL_DERIVED: &str = "channel_derived";
const KIND_PROVENANCE_REGEX: &str = "regex";
const KIND_PROVENANCE_LLM: &str = "llm";

/// L1-1 (v0.7.0) — typed memory-kind discriminator stored in the
/// `memories.memory_kind` column (schema v30).
///
/// `Observation` and `Reflection` exist since v0.7.0. `Persona`
/// landed in v0.7.0 QW-2 (schema v36) as the substrate-native
/// Tencent-pattern L3 persona artefact.
///
/// v0.7.x Form 6 (issue #759) — Batman taxonomy extension. The
/// `Concept | Entity | Claim | Relation | Event | Conversation |
/// Decision` variants give downstream readers a richer atom-type
/// vocabulary aligned with the Batman framework's exemplar
/// (Tolaria's frontmatter-as-type schema). All seven variants
/// serialize as snake_case strings via the existing
/// `memory_kind TEXT` column — no schema migration is required
/// because the column has no CHECK constraint. Old rows with no
/// kind read as `Observation` (the SQL `DEFAULT 'observation'`).
///
/// v0.8.0 Pillar 2 (#1709) — typed-cognition extension. The
/// `Goal | Plan | Step` variants give the substrate first-class
/// vocabulary for an agent's typed cognition: a `Goal` is a desired
/// end-state, a `Plan` is the ordered strategy to reach it, and a
/// `Step` is one executable unit within that plan. Like the Form-6
/// variants they serialize as snake_case strings on the same
/// `memory_kind TEXT` column with no migration required.
/// A future-schema variant a binary doesn't recognise reads as
/// `Observation` via the `unwrap_or_default()` chain in
/// `row_to_memory` (forward-compat).
///
/// `Observation` is the default for every memory created before v30 (the
/// `DEFAULT 'observation'` SQL column handles the backfill contract for
/// rows that pre-date the migration; new inserts that omit the field also
/// land at `Observation`). `Reflection` is set by the `memory_reflect`
/// write path in addition to the existing `metadata.type='reflection'`
/// back-compat marker. `Persona` is set by the QW-2
/// `PersonaGenerator` and the `memory_persona_generate` MCP tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MemoryKind {
    /// Default — a direct observation or note from the caller.
    #[default]
    Observation,
    /// A memory synthesised by the reflection pass over lower-depth
    /// peers (set by `memory_reflect` and the curator reflection pass).
    Reflection,
    /// v0.7.0 QW-2 — Persona-as-artifact. A curator-generated
    /// Markdown profile summarising an entity, derived from a
    /// cluster of Reflection-kind memories about that entity. The
    /// `entity_id` + `persona_version` columns on `memories` are
    /// populated only for this variant.
    Persona,
    /// v0.7.x Form 6 — abstract definition / vocabulary term
    /// ("ownership is a Rust borrow-checker rule").
    Concept,
    /// v0.7.x Form 6 — named real-world thing (person, org, product,
    /// system component). Pairs with `entity_id` on the row when the
    /// caller has registered the entity in the KG.
    Entity,
    /// v0.7.x Form 6 — factual assertion the caller is recording
    /// ("the build broke at 14:32 UTC"). Distinct from
    /// `Observation` in that a `Claim` is a propositional commitment;
    /// a `Reflection` chain may agree or contradict it.
    Claim,
    /// v0.7.x Form 6 — typed pair / triple. Anchors a KG relation
    /// inside the memory substrate so an operator can query the
    /// relation set with the same recall pipeline used for free-text.
    Relation,
    /// v0.7.x Form 6 — temporally-bounded happening
    /// ("deploy at 09:00", "incident at 14:32"). Distinct from
    /// `Observation` only when the caller wants the
    /// downstream-filtering surface to separate "what I saw" from
    /// "what happened".
    Event,
    /// v0.7.x Form 6 — captured dialogue turn (the substrate also
    /// stores conversations as `Observation`-kind today; this kind
    /// makes the type explicit for callers that want to filter to
    /// just conversational atoms).
    Conversation,
    /// v0.7.x Form 6 (L1-6 reservation) — choice point with
    /// rationale. Distinct from `Reflection` in that a `Decision`
    /// commits to a course of action; reflections summarise. The
    /// L1-6 work (v0.8.0) will likely add columns for
    /// rationale / alternatives, but the variant lands now so
    /// callers can start typing decisions.
    Decision,
    /// v0.8.0 Pillar 2 (#1709) — typed-cognition: a desired
    /// end-state / objective the agent is working toward. Distinct
    /// from `Decision` (a committed choice) in that a `Goal` names the
    /// target, not the path to it; a `Plan` enumerates that path and a
    /// `Step` is one executable unit within it.
    Goal,
    /// v0.8.0 Pillar 2 (#1709) — typed-cognition: an ordered strategy
    /// to reach a `Goal`. A `Plan` decomposes an objective into the
    /// sequence of `Step`s the agent intends to execute; downstream
    /// readers can filter to plans to reconstruct an agent's intended
    /// course of action.
    Plan,
    /// v0.8.0 Pillar 2 (#1709) — typed-cognition: a single executable
    /// unit within a `Plan`. The finest-grained typed-cognition atom —
    /// one actionable item whose completion advances the parent `Plan`
    /// toward its `Goal`.
    Step,
    /// v1.0.0 epistemic typing (#1945, spec §4) — RECEIVED hearsay: a
    /// claim the agent was *told* by another party, sitting epistemically
    /// BELOW `Observation` (the agent did not witness it). Distinct from
    /// `Claim` (a first-person propositional commitment) in that `Told`
    /// explicitly marks second-hand provenance. This slug is committed
    /// into the signed `SignableWrite` v2 genesis bytes (spec §2.2 [4]),
    /// so it is a T4-frozen wire value at v1.0.
    Told,
    /// v1.0.0 epistemic typing (#1945, spec §4) — a RECEIVED imperative:
    /// an instruction / directive the agent was given (fixes the L1
    /// operator-directive mis-stamp where directives were coerced to
    /// `Observation`). Signed genesis byte (spec §2.2 [4]); T4-frozen.
    Instruction,
    /// v1.0.0 epistemic typing (#1945, spec §4) — an ENACTED `do(X)`
    /// ground-truth: the do-calculus complement of `Observation`. Marks a
    /// memory recording an intervention the agent itself performed on the
    /// world (not merely observed). Signed genesis byte (spec §2.2 [4]);
    /// T4-frozen.
    Intervention,
}

impl MemoryKind {
    /// Column-wire string (matches the SQL `DEFAULT 'observation'` value).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Observation => KIND_OBSERVATION,
            Self::Reflection => KIND_REFLECTION,
            Self::Persona => "persona",
            Self::Concept => "concept",
            Self::Entity => "entity",
            Self::Claim => "claim",
            Self::Relation => "relation",
            Self::Event => "event",
            Self::Conversation => "conversation",
            Self::Decision => "decision",
            Self::Goal => "goal",
            Self::Plan => "plan",
            Self::Step => "step",
            Self::Told => KIND_TOLD,
            Self::Instruction => KIND_INSTRUCTION,
            Self::Intervention => KIND_INTERVENTION,
        }
    }

    /// Parse the column-wire string. Returns `None` on unrecognised values
    /// so callers can fall back to `Observation` (forward-compat with
    /// future variants that land in a newer DB on an older binary).
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            KIND_OBSERVATION => Some(Self::Observation),
            KIND_REFLECTION => Some(Self::Reflection),
            "persona" => Some(Self::Persona),
            "concept" => Some(Self::Concept),
            "entity" => Some(Self::Entity),
            "claim" => Some(Self::Claim),
            "relation" => Some(Self::Relation),
            "event" => Some(Self::Event),
            "conversation" => Some(Self::Conversation),
            "decision" => Some(Self::Decision),
            "goal" => Some(Self::Goal),
            "plan" => Some(Self::Plan),
            "step" => Some(Self::Step),
            KIND_TOLD => Some(Self::Told),
            KIND_INSTRUCTION => Some(Self::Instruction),
            KIND_INTERVENTION => Some(Self::Intervention),
            _ => None,
        }
    }

    /// Enumerate every variant in declaration order. Used by the
    /// capabilities surface (Form 6 `CapabilityMemoryKindVocab`) and
    /// by the recall filter parser when the caller passes `"all"`.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Observation,
            Self::Reflection,
            Self::Persona,
            Self::Concept,
            Self::Entity,
            Self::Claim,
            Self::Relation,
            Self::Event,
            Self::Conversation,
            Self::Decision,
            Self::Goal,
            Self::Plan,
            Self::Step,
            Self::Told,
            Self::Instruction,
            Self::Intervention,
        ]
    }

    /// v0.7.x Form 6 — parse a comma-separated list of kind names
    /// into a deduplicated `Vec<MemoryKind>`.
    ///
    /// Two distinct empty cases are intentionally preserved (Cluster E
    /// audit COR-4 — issue #767):
    ///   * Input is **empty** (whitespace-only or zero non-empty tokens
    ///     after trim) → `None`. Callers treat this as "no filter
    ///     declared, return everything".
    ///   * Input is **non-empty but every token is unrecognised** (e.g.
    ///     `"reflektion,observetion"`) → `Some(vec![])`. Callers treat
    ///     this as "an intentional filter was declared and matched
    ///     nothing", returning zero rows. Collapsing this case to
    ///     `None` (the pre-COR-4 behaviour) silently inverted a typo
    ///     into "show ALL kinds", which is the bug the v0.7.0 audit
    ///     flagged.
    ///
    /// Known tokens are deduplicated; unknown tokens are dropped
    /// silently (forward-compat — a future variant emitted by a newer
    /// client should not break recall on an older binary), but the
    /// distinction above means dropping every token does NOT collapse
    /// into "no filter".
    #[must_use]
    pub fn parse_csv(s: &str) -> Option<Vec<Self>> {
        let mut out: Vec<Self> = Vec::new();
        let mut saw_any_token = false;
        for tok in s.split(',') {
            let t = tok.trim();
            if t.is_empty() {
                continue;
            }
            saw_any_token = true;
            if let Some(k) = Self::from_str(t)
                && !out.contains(&k)
            {
                out.push(k);
            }
        }
        if !saw_any_token {
            // Input was empty / whitespace-only — caller treats as
            // "no filter declared".
            None
        } else {
            // At least one non-empty token was supplied. Return the
            // recognised set verbatim — including the empty-vec case
            // when every token was unknown, so the caller can apply a
            // strict "match nothing" filter rather than silently
            // collapsing to "match everything".
            Some(out)
        }
    }
}

impl std::fmt::Display for MemoryKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// v0.8.0 Pillar 2 (#1709) — typed-cognition lifecycle state stored on the
/// `memories.lifecycle_state` column (schema v64).
///
/// The already-shipped Goal/Plan/Step [`MemoryKind`]s (commit 466a7c96)
/// gain a first-class lifecycle here: an agent can mark a Goal
/// `open → active → done`, a Plan `active → blocked → active → done`, etc.
/// The legal transition graph is enforced by
/// [`LifecycleState::can_transition_to`] at the write boundary (the MCP
/// `memory_update` path), NOT a SQL CHECK — so a future state needs no
/// migration (mirrors [`crate::models::action::ActionState`]).
///
/// Transition graph:
/// `open → {active, abandoned}`,
/// `active → {blocked, done, abandoned}`,
/// `blocked → {active, abandoned}`,
/// terminal `done` / `abandoned` accept no outbound edge (and there are
/// no self-loops).
///
/// `Open` is the initial state for every memory (the SQL
/// `DEFAULT 'open'` on the column handles the backfill contract for rows
/// that pre-date the v64 migration; new inserts that omit the field also
/// land at `Open`). An unrecognised value from a future schema read by an
/// older binary falls back to `Open` via the `unwrap_or_default()` chain
/// in `row_to_memory` (forward-compat).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    /// Initial / default — created, not yet being worked.
    #[default]
    Open,
    /// Actively being worked toward completion.
    Active,
    /// Stalled on an external dependency / gate. Re-entrant to `Active`.
    Blocked,
    /// Completed successfully (terminal).
    Done,
    /// Withdrawn before completion (terminal).
    Abandoned,
    /// v0.9.0 G13-mem (#1859) — logical delete: the row is retained in
    /// `memories` (id + cid preserved) so lineage-DAG traversal can still
    /// reach it as a provenance ancestor, but it is excluded from ordinary
    /// recall/list. Set ONLY by the system consolidation-tombstone path via
    /// a raw UPDATE (it is not a caller-reachable [`Self::can_transition_to`]
    /// target); terminal, mirroring [`crate::revisions::RecordKind::Tombstone`].
    Tombstoned,
    /// v1.0.0 R19/A3 (#1948, decision `560c8007`) — system-only quarantine:
    /// the row is STORED (bytes converge, CRDT-safe) but structurally hidden
    /// from every ordinary read/egress lane by the fail-CLOSED
    /// [`lifecycle_visible_clause`] allow-list. Set ONLY by the system
    /// route-in path (provenance-less inbound federation-receive under
    /// `AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED`) via a raw UPDATE — it is
    /// ABSENT from [`Self::can_transition_to`] and REJECTED by
    /// [`crate::validate::validate_lifecycle_state`] as caller input (no
    /// self-exfiltration, no self-quarantine). Terminal; cleared only via
    /// the route-out dequarantine helpers.
    Quarantined,
}

impl LifecycleState {
    /// Column-wire string (matches the SQL `DEFAULT 'open'` value).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Active => "active",
            Self::Blocked => "blocked",
            Self::Done => "done",
            Self::Abandoned => "abandoned",
            Self::Tombstoned => "tombstoned",
            Self::Quarantined => "quarantined",
        }
    }

    /// Parse the column-wire string. Returns `None` on unrecognised values
    /// so callers can fall back to `Open` (forward-compat with future
    /// variants that land in a newer DB on an older binary).
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "open" => Some(Self::Open),
            "active" => Some(Self::Active),
            "blocked" => Some(Self::Blocked),
            "done" => Some(Self::Done),
            "abandoned" => Some(Self::Abandoned),
            "tombstoned" => Some(Self::Tombstoned),
            "quarantined" => Some(Self::Quarantined),
            _ => None,
        }
    }

    /// Enumerate every variant in declaration order. Used by the
    /// transition-enforcement error message + the capabilities surface.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Open,
            Self::Active,
            Self::Blocked,
            Self::Done,
            Self::Abandoned,
            Self::Tombstoned,
            Self::Quarantined,
        ]
    }

    /// Terminal states accept no outbound transition. `Tombstoned` (the
    /// v0.9.0 G13-mem logical-delete state) and `Quarantined` (the v1.0.0
    /// R19/A3 system-only quarantine) are terminal like `Done` / `Abandoned`.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Done | Self::Abandoned | Self::Tombstoned | Self::Quarantined
        )
    }

    /// System-only states — never settable by a caller. They are ABSENT
    /// from [`Self::can_transition_to`] (so the `memory_update` transition
    /// path can never reach them) AND rejected by
    /// [`crate::validate::validate_lifecycle_state`] as caller input. Set
    /// only by the system tombstone / quarantine raw-UPDATE paths.
    #[must_use]
    pub fn is_system_only(self) -> bool {
        matches!(self, Self::Tombstoned | Self::Quarantined)
    }

    /// Whether this state is surfaced on ordinary read/egress lanes
    /// (recall, list, search, export, forensic bundle, federation
    /// catch-up, kg traversal). The Rust mirror of the SQL
    /// [`lifecycle_visible_clause`] allow-list — fail-CLOSED: only the
    /// [`RECALL_VISIBLE_LIFECYCLE_STATES`] set is visible; `Tombstoned`,
    /// `Quarantined`, and any future/unknown state are hidden. Used by the
    /// HNSW/linear-scan recall branches that filter loaded [`Memory`] rows
    /// in Rust rather than in SQL.
    #[must_use]
    pub fn is_recall_visible(self) -> bool {
        RECALL_VISIBLE_LIFECYCLE_STATES.contains(&self)
    }

    /// v1.0.0 R19/A3 (#1948) route-OUT — the state a quarantined row returns
    /// to when it is dequarantined (either dequarantine-on-attest, when the
    /// author's write later verifies, or an operator dequarantine).
    ///
    /// Only a [`Self::Quarantined`] row dequarantines; every other state
    /// yields `None` (a no-op — nothing to clear). The target is
    /// [`Self::Open`] (the initial working state) so the row rejoins ordinary
    /// [`lifecycle_visible_clause`] visibility. Applied via a raw UPDATE
    /// (`Quarantined` is absent from [`Self::can_transition_to`], so this is
    /// deliberately NOT a caller transition).
    #[must_use]
    pub fn dequarantine_target(self) -> Option<Self> {
        matches!(self, Self::Quarantined).then_some(Self::Open)
    }

    /// Whether `self → to` is a legal lifecycle transition. No self-loops;
    /// terminals (`Done` / `Abandoned`) go nowhere.
    #[must_use]
    pub fn can_transition_to(self, to: Self) -> bool {
        matches!(
            (self, to),
            (Self::Open, Self::Active)
                | (Self::Open, Self::Abandoned)
                | (Self::Active, Self::Blocked)
                | (Self::Active, Self::Done)
                | (Self::Active, Self::Abandoned)
                | (Self::Blocked, Self::Active)
                | (Self::Blocked, Self::Abandoned)
        )
    }
}

impl std::fmt::Display for LifecycleState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// v1.0.0 R19/A3 (#1948, decision `560c8007`) — the fail-CLOSED allow-list
/// of lifecycle states that are surfaced on ordinary read/egress lanes.
///
/// This is the ONE canonical vocabulary for read-path visibility. It is an
/// **allow-list, not a deny-list**: any state NOT in this set — the
/// system-only [`LifecycleState::Tombstoned`] / [`LifecycleState::Quarantined`],
/// or any future/unknown value read by an older binary — is invisible.
/// Adding a caller-visible state is a one-line edit here; forgetting to add
/// a new system-only state fails safe (hidden by default).
///
/// The SQL twin is [`lifecycle_visible_clause`]; the Rust twin is
/// [`LifecycleState::is_recall_visible`]. Both derive their vocabulary from
/// this slice — the allow-list is never re-spelled as scattered literals.
pub const RECALL_VISIBLE_LIFECYCLE_STATES: [LifecycleState; 5] = [
    LifecycleState::Open,
    LifecycleState::Active,
    LifecycleState::Blocked,
    LifecycleState::Done,
    LifecycleState::Abandoned,
];

/// v1.0.0 R19/A3 (#1948, decision `560c8007`) — build the shared
/// fail-CLOSED lifecycle-visibility SQL fragment for a read/egress lane.
///
/// Returns `AND (<col> IS NULL OR <col> IN ('open', ...))` with a leading
/// `AND ` so it drops into a `WHERE` that already has preceding predicates
/// (mirrors the storage-layer `visibility_clause` /
/// `archived_source_clause` fragments). The allow-list is generated from
/// [`RECALL_VISIBLE_LIFECYCLE_STATES`] via `as_str()` — never hardcoded
/// literals — so the vocabulary lives in exactly one place.
///
/// `NULL` is treated as **visible-legacy**: the v64 column is
/// `lifecycle_state TEXT NOT NULL DEFAULT 'open'`, so live `memories` rows
/// are never NULL, but `COALESCE`/`LEFT JOIN` read shapes can surface a
/// NULL; those legacy/derived reads keep their prior visibility.
///
/// The fragment is **placeholder-free** (literal allow-list) so injecting
/// it never renumbers a call site's bound parameters. It is used verbatim
/// by BOTH backends (SQLite `?N` and Postgres `$N` queries) because it
/// binds nothing.
///
/// `table_alias` is the memories-table alias in the host query (`"m"`,
/// `"memories"`, or `""` for an unqualified column).
#[must_use]
pub fn lifecycle_visible_clause(table_alias: &str) -> String {
    let col = if table_alias.is_empty() {
        super::field_names::LIFECYCLE_STATE.to_string()
    } else {
        format!("{table_alias}.{}", super::field_names::LIFECYCLE_STATE)
    };
    let mut list = String::new();
    for (i, state) in RECALL_VISIBLE_LIFECYCLE_STATES.iter().enumerate() {
        if i > 0 {
            list.push_str(", ");
        }
        list.push('\'');
        list.push_str(state.as_str());
        list.push('\'');
    }
    format!("AND ({col} IS NULL OR {col} IN ({list}))")
}

/// v0.7.0 Form 5 (issue #758) — typed discriminator for the provenance
/// of a memory's `confidence` value.
///
/// Stored on `memories.confidence_source TEXT NOT NULL DEFAULT
/// 'caller_provided'` (schema v39 sqlite / v38 postgres). The auto-
/// derive engine in [`crate::confidence::derive`] writes
/// `AutoDerived` when [`crate::confidence::derive`] computes a fresh
/// value; the calibration sweep writes `Calibrated` when it replaces
/// the live value with a per-source baseline; the decay updater writes
/// `Decayed` after applying [`crate::confidence::decay::decayed`] on
/// recall touch. The (overwhelming-majority) legacy + default bucket
/// is `CallerProvided`, matching the SQL `DEFAULT` clause.
///
/// The discriminator lets recall ranking and the forensic bundle
/// reason about the trust path of a confidence score without re-running
/// the derivation. The calibration CLI scans the partial index
/// `idx_memories_confidence_source` (which excludes `caller_provided`)
/// to enumerate derived / calibrated / decayed rows cheaply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceSource {
    /// The legacy and default bucket — the caller's value was accepted
    /// verbatim. Matches the SQL `DEFAULT 'caller_provided'` clause on
    /// the `confidence_source` column added in schema v39 (sqlite) /
    /// v38 (postgres).
    #[default]
    CallerProvided,
    /// The Form 5 auto-derive engine (`crate::confidence::derive`)
    /// computed the value at write time from row signals (atom
    /// derivation, prior-corroboration count, source age, namespace
    /// baseline). Opt-in via `AI_MEMORY_AUTO_CONFIDENCE=1`.
    AutoDerived,
    /// The calibration sweep (`ai-memory calibrate confidence
    /// --from-shadow`) replaced the live value with a per-source
    /// baseline computed from observed shadow-mode samples.
    Calibrated,
    /// The freshness-decay updater (`crate::confidence::decay`) wrote
    /// a decayed copy of the previous value, bumping
    /// `confidence_decayed_at`. Fires when
    /// `AI_MEMORY_CONFIDENCE_DECAY=1` or the namespace policy
    /// `confidence_decay_half_life_days` is set.
    Decayed,
    /// v0.7.0 issue #1242 — the curator engine (atomisation
    /// `LlmCurator`, persona generator) computed the value at row-
    /// mint time without an explicit caller-supplied number. Atom
    /// rows inherit `confidence` from their parent memory; persona
    /// rows pin `confidence = 1.0` per the QW-2 brief. In both
    /// cases the value is engine-derived, not caller-supplied, and
    /// must be discoverable to the calibration sweep + the partial
    /// index `idx_memories_confidence_source` (which excludes
    /// `caller_provided`). Pre-#1242 these rows mis-labelled
    /// `confidence_source = CallerProvided`, hiding them from the
    /// derived-row enumeration and violating the audit-honesty
    /// invariant.
    CuratorDerived,
    /// v0.7.x issue #1591 — the caller OMITTED `confidence` and the
    /// store surface stamped the compiled [`DEFAULT_CONFIDENCE`]
    /// fallback. Pre-#1591 these rows mis-labelled
    /// `confidence_source = 'caller_provided'` — a false provenance
    /// claim that made an unexamined 1.0 indistinguishable from a
    /// caller's deliberate full-confidence assertion. The Form-5
    /// calibration / decay engines treat this bucket exactly like
    /// `caller_provided` (the value is not engine-derived), but
    /// auditors and recall ranking can now discount the compiled
    /// fallback honestly.
    Default,
}

impl ConfidenceSource {
    /// Column-wire string (matches the SQL `DEFAULT 'caller_provided'`
    /// value and the four documented discriminator values).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CallerProvided => "caller_provided",
            Self::AutoDerived => "auto_derived",
            Self::Calibrated => "calibrated",
            Self::Decayed => "decayed",
            Self::CuratorDerived => "curator_derived",
            Self::Default => "default",
        }
    }

    /// Parse the column-wire string. Returns `None` on unrecognised
    /// values so callers can fall back to `CallerProvided` (forward-
    /// compat with future variants that land in a newer DB on an
    /// older binary).
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "caller_provided" => Some(Self::CallerProvided),
            "auto_derived" => Some(Self::AutoDerived),
            "calibrated" => Some(Self::Calibrated),
            "decayed" => Some(Self::Decayed),
            "curator_derived" => Some(Self::CuratorDerived),
            "default" => Some(Self::Default),
            _ => None,
        }
    }
}

impl std::fmt::Display for ConfidenceSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// v1.0.0 epistemic typing (#1945, spec §4) — typed discriminator for
/// HOW a memory's [`MemoryKind`] was assigned.
///
/// Stored on the additive nullable `memories.kind_provenance TEXT`
/// column (schema v79) as **unsigned metadata** — it is NOT part of the
/// signed `SignableWrite` v2 envelope (unlike the `memory_kind` slug
/// itself, spec §2.2 [4]). It records *how* the kind was assigned, not
/// that the kind is true, so it is an ESTIMABLE provenance marker (spec
/// §4), a clone of the [`ConfidenceSource`] precedent. Surfaced in recall
/// so a consumer can distinguish a caller-DECLARED kind from a
/// channel-DERIVED one.
///
/// This is a closed vocabulary. `from_str` returns `None` off-vocab so
/// callers fall back to `None`/`Declared` (forward-compat with a future
/// variant landing in a newer DB read by an older binary). The
/// default-flip that makes caller silence sink to `Claim` is PHASED to
/// v0.10.0 (#1972) and deliberately NOT part of this stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum KindProvenance {
    /// The caller explicitly declared the `memory_kind` on the write.
    #[default]
    Declared,
    /// The kind was derived from the ingest channel / transport context
    /// (e.g. an operator-directive channel stamping `Instruction`).
    ChannelDerived,
    /// The kind was assigned by a deterministic regex classifier
    /// (`pre_store::auto_classify_kind` regex pass).
    Regex,
    /// The kind was assigned by an LLM classifier.
    Llm,
}

impl KindProvenance {
    /// Column-wire string for the `kind_provenance` column.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Declared => KIND_PROVENANCE_DECLARED,
            Self::ChannelDerived => KIND_PROVENANCE_CHANNEL_DERIVED,
            Self::Regex => KIND_PROVENANCE_REGEX,
            Self::Llm => KIND_PROVENANCE_LLM,
        }
    }

    /// Parse the column-wire string. Returns `None` off-vocab (forward-
    /// compat), mirroring [`MemoryKind::from_str`].
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            KIND_PROVENANCE_DECLARED => Some(Self::Declared),
            KIND_PROVENANCE_CHANNEL_DERIVED => Some(Self::ChannelDerived),
            KIND_PROVENANCE_REGEX => Some(Self::Regex),
            KIND_PROVENANCE_LLM => Some(Self::Llm),
            _ => None,
        }
    }

    /// Enumerate every variant in declaration order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[Self::Declared, Self::ChannelDerived, Self::Regex, Self::Llm]
    }
}

impl std::fmt::Display for KindProvenance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Metadata carrier key for [`KindProvenance`] (#1945, spec §4).
///
/// The provenance is stamped into `metadata` at each write entry point —
/// exactly the `attest_level` precedent — so it round-trips through the
/// `memories.metadata` column and is surfaced in recall automatically. The
/// physical v79 `kind_provenance` column is a denormalised, SQL-queryable
/// copy the persist funnel derives from this key (the `mentioned_entity_id`
/// precedent). Unsigned: it is NOT part of the `SignableWrite` v2 envelope.
pub const METADATA_KIND_PROVENANCE_KEY: &str = "kind_provenance";

impl KindProvenance {
    /// Stamp this provenance into a memory's `metadata` object (idempotent
    /// overwrite). A non-object metadata value is left untouched (the write
    /// paths always build an object metadata).
    pub fn stamp(self, metadata: &mut serde_json::Value) {
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert(
                METADATA_KIND_PROVENANCE_KEY.to_string(),
                serde_json::Value::String(self.as_str().to_string()),
            );
        }
    }

    /// Read the provenance stamped in a memory's `metadata`, if any and if
    /// on-vocab. `None` for legacy/unstamped rows (NULL stays legal) and for
    /// an off-vocab value (forward-compat with a future variant).
    #[must_use]
    pub fn from_metadata(metadata: &serde_json::Value) -> Option<Self> {
        metadata
            .get(METADATA_KIND_PROVENANCE_KEY)
            .and_then(serde_json::Value::as_str)
            .and_then(Self::from_str)
    }
}

/// v0.7.0 Form 5 (issue #758) — JSON snapshot of the signals that
/// produced an auto-derived or calibrated confidence value.
///
/// Stored on `memories.confidence_signals TEXT NULL` (schema v39
/// sqlite / v38 postgres) as a JSON-encoded envelope. NULL on legacy
/// rows and on rows whose `confidence_source = 'caller_provided'`.
/// Also written verbatim into the `confidence_shadow_observations.signals`
/// column per recall when shadow mode is enabled.
///
/// An auditor can reconstruct the derivation after the fact by
/// inspecting this snapshot — the recall ranker and the forensic
/// bundle preserve it across reads, so a downstream review never
/// needs to re-query the substrate at the then-current state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfidenceSignals {
    /// Age (in days) of the source memory at the moment of derivation.
    /// Drives the `freshness_factor` exponent.
    pub source_age_days: f64,
    /// Whether the row is an atom of an existing memory (`atom_of IS
    /// NOT NULL`). Atom rows inherit higher base confidence because
    /// their provenance is anchored to a curator-validated parent.
    pub atom_derivation: bool,
    /// Count of related memories (via `memory_links`) at the moment of
    /// derivation. More corroboration → higher confidence; the
    /// formula uses `log10(1 + count)` to keep the bump sub-linear.
    pub prior_corroboration_count: i64,
    /// Pre-computed freshness factor `exp(-age / half_life)` clamped
    /// to `[0, 1]`. Stored alongside `source_age_days` so a future
    /// review can verify the half-life used at write time.
    pub freshness_factor: f64,
    /// Per-source baseline from the calibration table (median derived
    /// confidence for the row's `(namespace, source)` pair). `0.5`
    /// when no calibrated baseline exists yet.
    pub baseline_per_source: f64,
}

impl Default for ConfidenceSignals {
    fn default() -> Self {
        Self {
            source_age_days: 0.0,
            atom_derivation: false,
            prior_corroboration_count: 0,
            freshness_factor: 1.0,
            baseline_per_source: 0.5,
        }
    }
}

/// Memory-lifecycle tier — short (6h TTL) / mid (7d TTL) / long
/// (permanent). Drives the create-time backstop, the touch-time
/// sliding window, the auto-promotion at 5 accesses (mid → long),
/// the GC sweep, and the recall ranker's per-tier bonus.
///
/// # Disambiguation (issue #970)
///
/// The codebase has three enums whose names end in `Tier`. They are
/// orthogonal — same descriptive substring, distinct domains:
///
/// - [`Tier`] (this enum) — memory-lifecycle TTL bucket.
/// - [`ConfidenceTier`] — confidence-value bucket (Confirmed /
///   Likely / Ambiguous) derived from `Memory.confidence` thresholds.
///   Operator dashboards / human-review queues filter on it.
/// - [`crate::config::FeatureTier`] — host capability tier
///   (Keyword / Semantic / Smart / Autonomous) that gates which AI
///   features the host can fit in RAM.
///
/// They do not share variants, do not share wire strings, and are
/// never substitutable. See `docs/internal/enum-proliferation-audit-970.md`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Short,
    Mid,
    Long,
}

impl Tier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Short => "short",
            Self::Mid => "mid",
            Self::Long => "long",
        }
    }

    /// Parse a tier wire string into the typed enum.
    ///
    /// The string literals in the match arms below are the **canonical
    /// deserializer** for the `Tier` wire form. They are the one place
    /// in the codebase where raw `"short"` / `"mid"` / `"long"` literals
    /// legitimately appear, because this is the boundary where a
    /// caller-supplied `&str` (HTTP body field, MCP JSON param, CLI
    /// flag value, TOML config field) gets dispatched into the typed
    /// enum. They are intentionally byte-equal to
    /// [`Tier::as_str`]'s outputs so the round-trip is identity.
    /// Anywhere else that *constructs* a tier wire value MUST route
    /// through `Tier::<X>.as_str()` instead of restamping a fresh
    /// literal. See pm-v3.1 PR6 (#1174) for the sweep that pinned this
    /// invariant.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "short" => Some(Self::Short),
            "mid" => Some(Self::Mid),
            "long" => Some(Self::Long),
            _ => None,
        }
    }

    /// v1.0.0 #3130 — the canonical, human-readable list of the values
    /// [`Tier::from_str`] accepts. Rendered into every fail-closed tier
    /// refusal so an operator who mistyped is told what IS valid, and
    /// single-sourced here so the message cannot drift from the match
    /// arms above (it previously appeared as a hand-copied literal in
    /// `cli::store` and `cli::io`).
    pub const VALUES_HINT: &'static str = "short, mid, long";

    /// v1.0.0 #3130 — FAIL-CLOSED tier parse.
    ///
    /// [`Tier::from_str`] answers `None` for an unrecognised value, and
    /// every filter surface in the substrate reads `None` as **"no tier
    /// constraint"**. Chaining the two (`.and_then(Tier::from_str)`)
    /// therefore turned a typo into a WIDENING of the operation instead
    /// of a refusal: `forget --tier Long` matched every tier and erased
    /// the whole corpus while printing success, and `search` / `list`
    /// returned unfiltered rows. Any surface that accepts a
    /// caller-supplied tier string MUST route through this (or
    /// [`Tier::parse_optional`]) so an unrecognised value is a loud
    /// refusal, never a silently-dropped filter.
    ///
    /// # Errors
    /// The caller-facing refusal naming [`Tier::VALUES_HINT`], when
    /// `raw` is not one of the canonical wire strings.
    pub fn parse_strict(raw: &str) -> Result<Self, String> {
        Self::from_str(raw)
            .ok_or_else(|| format!("invalid tier: {raw} (use {hint})", hint = Self::VALUES_HINT))
    }

    /// v1.0.0 #3130 — optional-filter form of [`Tier::parse_strict`].
    ///
    /// An ABSENT tier stays `None` — genuinely unconstrained, the
    /// documented default of every filter surface. A PRESENT-but-
    /// unrecognised tier is REFUSED. That is exactly the distinction the
    /// `.and_then(Tier::from_str)` shape collapsed.
    ///
    /// # Errors
    /// Propagates [`Tier::parse_strict`]'s refusal.
    pub fn parse_optional(raw: Option<&str>) -> Result<Option<Self>, String> {
        raw.map(Self::parse_strict).transpose()
    }

    /// Numeric rank for tier comparison: Short=0, Mid=1, Long=2.
    #[cfg(test)]
    pub fn rank(&self) -> u8 {
        match self {
            Self::Short => 0,
            Self::Mid => 1,
            Self::Long => 2,
        }
    }

    /// The per-tier default TTL. Routes through the substrate's
    /// [`RetentionModel`](crate::retention::RetentionModel) so the retention
    /// posture is resolved in ONE place (TRACT-gap G15, #1829): the discrete
    /// per-tier values live in [`Tier::discrete_ttl_secs`], and this delegates
    /// via the model. Byte-identical to the pre-#1829 direct match — the
    /// `RetentionModel::DiscreteTtlTiers` arm returns exactly these values — so
    /// every eviction/TTL-floor caller is unchanged, but the model now has a
    /// real live consumer (this, the most-called TTL function) rather than
    /// being an inert anchor.
    #[must_use]
    pub fn default_ttl_secs(&self) -> Option<i64> {
        crate::retention::RetentionModel::current().ttl_secs_for(self)
    }

    /// The raw per-tier TTL under the CURRENT discrete-tier retention model
    /// (Short 6h / Mid 7d / Long permanent). The canonical value source; callers
    /// go through [`Tier::default_ttl_secs`] (which routes via
    /// [`RetentionModel`](crate::retention::RetentionModel)). Kept separate so a
    /// future continuous cost-of-access model (G15) adds a `RetentionModel`
    /// variant + its own resolution WITHOUT rewriting these baseline values.
    #[must_use]
    pub fn discrete_ttl_secs(&self) -> Option<i64> {
        match self {
            Self::Short => Some(6 * crate::SECS_PER_HOUR),
            Self::Mid => Some(crate::SECS_PER_WEEK),
            Self::Long => None,
        }
    }
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Memory {
    pub id: String,
    pub tier: Tier,
    pub namespace: String,
    pub title: String,
    pub content: String,
    pub tags: Vec<String>,
    pub priority: i32,
    /// 0.0-1.0 — how certain is this memory
    pub confidence: f64,
    /// Who/what created this row. Role-categorical, not vendor-specific.
    /// Canonical closed set lives in [`crate::validate::VALID_SOURCES`]
    /// at v0.7.0:
    ///   `user`, `nhi` ([`crate::validate::DEFAULT_NHI_SOURCE`] — the
    ///   vendor-neutral substrate default for AI-NHI-minted writes per
    ///   #1175), `claude` (deprecated; back-compat only, removal in
    ///   v0.8.x), `hook`, `api`, `cli`, `import`, `consolidation`,
    ///   `system`, `chaos`, `notify` (S32 inbox replication path).
    /// Validator surface: [`crate::validate::validate_source`].
    pub source: String,
    pub access_count: i64,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_accessed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default = "default_metadata")]
    pub metadata: Value,
    /// v0.7.0 Task 1/8 (recursive learning) — depth in the substrate-native
    /// reflection recursion tree. `0` for memories minted directly from a
    /// caller (or any pre-v0.7.0 row), positive for memories synthesised by
    /// the reflection pass over lower-depth peers. Operators can cap recursion
    /// depth at write time; readers can filter / sort by it.
    ///
    /// `#[serde(default)]` lets pre-v0.7.0 JSON payloads (and older federation
    /// peers) deserialize cleanly — missing → 0, which matches the SQL
    /// `DEFAULT 0` on the column added in schema v29 (SQLite) / v31 (Postgres).
    #[serde(default)]
    pub reflection_depth: i32,
    /// L1-1 (v0.7.0) — typed memory-kind discriminator.  Stored in
    /// `memories.memory_kind TEXT NOT NULL DEFAULT 'observation'` (schema v30).
    /// `Observation` for every pre-v30 row (SQL default); `Reflection` for
    /// memories minted by `memory_reflect` or the curator reflection pass.
    ///
    /// `#[serde(default)]` ensures round-trips with pre-v30 federation peers
    /// that don't yet emit the field.
    #[serde(default)]
    pub memory_kind: MemoryKind,
    /// v0.7.0 QW-2 — populated only when `memory_kind == Persona`.
    /// Identifies the subject of the persona. Stored on the SQL
    /// column `memories.entity_id TEXT NULL` (schema v36).
    /// `skip_serializing_if = "Option::is_none"` keeps the absent
    /// shape on the wire for pre-QW-2 federation peers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    /// v0.7.0 QW-2 — monotonic per-(entity_id, namespace) version
    /// counter for the Persona artefact. Populated only when
    /// `memory_kind == Persona`. Each `PersonaGenerator::generate`
    /// call writes a new row with `version + 1`; older rows stay
    /// queryable for audit / rollback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persona_version: Option<i32>,
    /// v0.7.0 Form 4 (issue #757) — fact-provenance citations array.
    /// Each entry carries a typed [`Citation`] envelope (uri,
    /// accessed_at, optional hash, optional span). Stored on the
    /// `memories.citations` TEXT column (schema v38) as a JSON-encoded
    /// array — legacy rows default to an empty vector via the SQL
    /// `DEFAULT '[]'` clause and the serde default below. Validator
    /// surface lives at `crate::validate::validate_citation`.
    ///
    /// **NSA CSI MCP Security mapping.** Part of the Form 4
    /// fact-provenance triple (`citations` + `source_uri` +
    /// `source_span`) that addresses NSA concerns (b) Insecure
    /// context or data serialization + (g) Poor or missing audit
    /// logs, and contributes to NSA recommendations (c) Validate
    /// parameters + (f) Filter and monitor output pipelines per the
    /// National Security Agency Cybersecurity Information document
    /// on MCP security (U/OO/6030316-26 | PP-26-1834, May 2026
    /// Version 1.0). Capability inventory anchor:
    /// `form_4_fact_provenance`. The mapping is described — without
    /// implying NSA endorsement of ai-memory or AlphaOne LLC — at
    /// `docs/compliance/nsa-csi-mcp.html` §3.2 / §3.7 / §4.3 / §4.6.
    #[serde(default)]
    pub citations: Vec<Citation>,
    /// v0.7.0 Form 4 (issue #757) — first-class URI-form pointer to
    /// the cited source body. Distinct from the role-label `source`
    /// column. Accepted schemes: `uri:` (HTTP URL), `doc:` (substrate
    /// doc id), `file:` (filesystem path). Validator surface lives at
    /// `crate::validate::validate_source_uri`. Mapped onto the
    /// `memories.source_uri` TEXT column (schema v38). NULL on legacy
    /// rows and on rows that do not yet carry a URI form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_uri: Option<String>,
    /// v0.7.0 Form 4 (issue #757) — byte-range into the parent source
    /// body. Populated by the WT-1-B atomisation writer for each atom
    /// (atom-grain span fact-provenance) and may be set by callers
    /// who can pin the offset of a memory inside its referenced
    /// source. Mapped onto the `memories.source_span` TEXT column
    /// (schema v38) as a JSON `{start, end}` envelope. Validator
    /// surface lives at `crate::validate::validate_source_span`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_span: Option<SourceSpan>,
    /// v0.7.0 Form 5 (issue #758) — typed discriminator naming the
    /// provenance of the `confidence` value. Stored on
    /// `memories.confidence_source TEXT NOT NULL DEFAULT
    /// 'caller_provided'` (schema v39 sqlite / v38 postgres). Defaults
    /// to `CallerProvided` for every legacy row and every write that
    /// arrives with the auto-derive engine disabled.
    #[serde(default)]
    pub confidence_source: ConfidenceSource,
    /// v0.7.0 Form 5 — JSON snapshot of the signals that produced an
    /// auto-derived or calibrated confidence value. Mapped onto
    /// `memories.confidence_signals TEXT NULL` (schema v39 sqlite /
    /// v38 postgres). NULL on legacy rows and on rows whose
    /// `confidence_source = CallerProvided`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_signals: Option<ConfidenceSignals>,
    /// v0.7.0 Form 5 — RFC3339 stamp of the last decay computation.
    /// Mapped onto `memories.confidence_decayed_at TEXT NULL` (schema
    /// v39 sqlite / v38 postgres). NULL on legacy rows and on rows
    /// never touched by the decay updater.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_decayed_at: Option<String>,
    /// v0.7.0 Provenance Gap 1 (issue #884, schema v45 sqlite) —
    /// optimistic-concurrency counter. Bumped on every mutation:
    /// `storage::update` AND the `(title, namespace)` upsert-merge arm
    /// of `storage::insert` (#1632). Two callers writing against the
    /// same `expected_version` race exactly one winner; the loser
    /// receives a typed `CONFLICT` envelope naming the current stored
    /// version. The confidence-decay sweep is the only documented
    /// non-bumping mutator (tests/non_version_bumping_sites_1036.rs).
    /// Legacy rows land at `version = 1` via the SQL DEFAULT
    /// clause. `#[serde(default = "default_memory_version")]` keeps
    /// pre-v45 federation peers / JSON payloads deserialising cleanly.
    #[serde(default = "default_memory_version")]
    pub version: i64,
    /// v0.8.0 Pillar 2 (#1709) — typed-cognition lifecycle state. Stored on
    /// `memories.lifecycle_state TEXT NOT NULL DEFAULT 'open'` (schema v64).
    /// `Open` for every legacy / pre-v64 row (SQL default) and every fresh
    /// store that omits the field; transitions are enforced on
    /// `memory_update` via [`LifecycleState::can_transition_to`].
    ///
    /// `#[serde(default)]` ensures round-trips with pre-v64 federation peers
    /// (and JSON payloads) that don't yet emit the field — missing → `Open`,
    /// matching the SQL `DEFAULT 'open'`.
    #[serde(default)]
    pub lifecycle_state: LifecycleState,
    /// v0.9.0 G8 (#1825) — the additive, content-addressed BLAKE3
    /// content-id (`b3:<hex>`) minted from this memory's GENESIS identity
    /// (`agent_id + namespace + screen(title) + memory_kind + created_at +
    /// SHA256(screen(content))`). Sits ALONGSIDE `id` (the UUID stays the
    /// PK / every FK / the federation LWW tiebreak); the cid is a second,
    /// content-derived name. Stored in `memories.cid TEXT` (schema v74),
    /// `NULL` on legacy rows the v74 backfill couldn't stamp (undecryptable
    /// or `version >= 2` re-stored rows). The storage-internal `cid_genesis`
    /// pre-image BLOB is NOT a `Memory` field — it is read on demand only by
    /// the verify path ([`crate::identity::cid::verify_cid`]).
    ///
    /// `#[serde(default, skip_serializing_if = "Option::is_none")]` keeps
    /// the absent shape off the wire for pre-v74 federation peers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    /// v1.0.0 #1834 (TRACT G20, schema v79) — claim-level bitemporal
    /// VALID-TIME lower bound: the RFC3339 instant from which this claim is
    /// asserted to hold IN THE WORLD. DISTINCT from `created_at` (transaction
    /// time — when the row was written): a backfilled fact can be valid_from a
    /// past instant, a future-effective policy from a future one. `None` =
    /// unbounded past (−∞), so a claim with no lower bound is valid at every
    /// `valid_at` query instant (legacy / default rows stay visible). Stored
    /// on `memories.valid_from TEXT NULL`. Mirrors the `memory_links`
    /// edge-level temporal columns. UNSIGNED, caller-CLAIMED metadata — NOT in
    /// the `SignableWrite` v2 envelope; the federation write-signature path
    /// does NOT attest it (trust-on-write, like `metadata.agent_id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    /// v1.0.0 #1834 (TRACT G20, schema v79) — claim-level bitemporal
    /// VALID-TIME upper bound (END-EXCLUSIVE): the RFC3339 instant AT which the
    /// claim stops being asserted. A `valid_at` query matches when
    /// `valid_until IS NULL OR valid_until > valid_at` (half-open
    /// `[valid_from, valid_until)`, SQL:2011 convention — a claim ending at T
    /// and one starting at T do not both match `valid_at = T`). `None` = still
    /// valid (unbounded future, +∞). Set/updated via `memory_update` to CLOSE a
    /// claim (the canonical bitemporal event); `valid_from` is immutable once
    /// set (a correction is a supersede, not a mutation). Stored on
    /// `memories.valid_until TEXT NULL`. Same UNSIGNED / non-attested posture
    /// as `valid_from`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
}

impl Memory {
    /// Total number of declared `pub <name>: <type>` fields on the
    /// `Memory` struct. SSOT for the "27-field struct at v0.8.0
    /// (26 at v0.7.0, was 15 at v0.6.x)" narrative in CLAUDE.md /
    /// README.md / ROADMAP.md / release-notes — the 27th field is the
    /// v0.8.0 Pillar-2 (#1709) `lifecycle_state` column; the 28th field is
    /// the v0.9.0 G8 (#1825) additive `cid` content-id column; the 29th + 30th
    /// are the v1.0.0 #1834 claim-bitemporal `valid_from` + `valid_until`
    /// VALID-TIME columns.
    /// Adding or removing a field requires
    /// bumping this const in the same commit, OR the parity test pin
    /// at `tests/memory_field_count_invariant.rs` fails the build.
    ///
    /// Multi-agent literal-sweep reference: scanner B finding F-B1.x
    /// (Memory shape drift), mirrors the
    /// `MemoryLinkRelation::COUNT` + `EXPECTED_CLI_SUBCOMMANDS_*`
    /// drift-blocker pattern landed in commits 960578cfd + 233e8a247.
    pub const FIELD_COUNT: usize = 30;

    /// v0.7.0 #1466 — the `expires_at` value a fresh store must persist.
    /// An explicit value the caller supplied wins; otherwise a non-`Long`
    /// row is stamped with `created_at + Tier::default_ttl_secs()` so it
    /// is reapable by GC (`expires_at IS NOT NULL AND expires_at < now`).
    /// `Long` rows have no TTL and stay immortal (returns `None`).
    ///
    /// Single SSOT for the tier-default backfill across every store
    /// backend (SQLite `storage::insert` + the `insert_with_conflict` /
    /// `insert_if_newer` / `consolidate` siblings, and the Postgres
    /// `store` path). Before this, those paths bound `expires_at`
    /// verbatim, so any internal caller that hand-built a `mid`/`short`
    /// Memory with `expires_at: None` created an immortal row GC could
    /// never collect. The interval comes from `Tier::default_ttl_secs()`
    /// — no hardcoded TTL literal — so it can never drift from the
    /// canonical per-tier TTL. Output mirrors the normal store path
    /// (`to_rfc3339`) so the string comparison in `gc()` stays
    /// monotonic; a malformed `created_at` falls back to `now` rather
    /// than silently dropping the expiry.
    #[must_use]
    pub fn effective_expires_at(&self) -> Option<String> {
        if self.expires_at.is_some() {
            return self.expires_at.clone();
        }
        let ttl = self.tier.default_ttl_secs()?;
        let base = chrono::DateTime::parse_from_rfc3339(&self.created_at)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now());
        Some((base + chrono::Duration::seconds(ttl)).to_rfc3339())
    }
}

/// Default for [`Memory::version`] on rows that pre-date schema v45
/// (or JSON payloads from clients that haven't learned about the
/// column yet). Matches the SQL DEFAULT clause on the column.
#[must_use]
pub fn default_memory_version() -> i64 {
    1
}

/// v0.7.0 Provenance Gap 5 (issue #888) — typed edit-source
/// discriminator gating the `storage::update` write-path branch.
///
/// * [`EditSource::Human`] (default) — direct in-place mutation, the
///   v0.6.x / pre-Gap-5 behaviour. Content is overwritten; the row's
///   `version` is bumped; no archive is created.
/// * [`EditSource::Llm`] / [`EditSource::Hook`] — append-and-archive.
///   A NEW memory row is minted carrying the patched content; a
///   `supersedes` link is written pointing new→old; the OLD row is
///   archived with `archive_reason = 'superseded'` so callers can
///   rewind via `memory_archive_list` to read the pre-edit state.
///
/// The split exists so caller intent (human-typed correction vs.
/// curator/LLM rewrite) is preserved in the audit trail. Mem9's
/// pattern: in-place for human edits, append-and-archive for
/// programmatic rewrites where the new content semantically replaces
/// the old.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EditSource {
    /// Direct in-place mutation of the existing row. Default.
    #[default]
    Human,
    /// Append-and-archive: mint a NEW row + supersedes link + archive
    /// the OLD row with `archive_reason='superseded'`.
    Llm,
    /// Append-and-archive: same shape as [`EditSource::Llm`] but
    /// records that a substrate hook triggered the rewrite.
    Hook,
    /// v0.7.x issue #1600 — direct in-place mutation performed by an
    /// AI/NHI agent. Mutation semantics are IDENTICAL to
    /// [`EditSource::Human`] (does NOT route through
    /// append-and-archive); the variant exists so the audit trail can
    /// distinguish a human-typed correction from an agent-initiated
    /// in-place edit. When `edit_source` is omitted on `memory_update`
    /// the default is derived from the resolved caller id via
    /// [`EditSource::default_for_agent_id`].
    Agent,
}

impl EditSource {
    /// #1600 — the closed wire vocabulary, in declaration order. The
    /// `memory_update` validation error names the valid set from this
    /// const so the message can never drift from the parser below.
    pub const ALL: [Self; 4] = [Self::Human, Self::Llm, Self::Hook, Self::Agent];

    /// Column-wire string used in audit log entries + the archive
    /// row's `archive_reason`-adjacent metadata.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Llm => "llm",
            Self::Hook => "hook",
            Self::Agent => "agent",
        }
    }

    /// Parse the column-wire string. Returns `None` on unrecognised
    /// values; per #1600 the MCP `memory_update` surface now surfaces
    /// `None` as a validation ERROR naming [`EditSource::ALL`] instead
    /// of silently defaulting to [`EditSource::Human`].
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "human" => Some(Self::Human),
            "llm" => Some(Self::Llm),
            "hook" => Some(Self::Hook),
            "agent" => Some(Self::Agent),
            _ => None,
        }
    }

    /// #1600 — default edit-source for an UPDATE whose caller omitted
    /// `edit_source`, derived from the resolved caller agent id: ids
    /// under [`crate::identity::sentinels::AI_AGENT_ID_PREFIX`]
    /// (`ai:…`) default to [`EditSource::Agent`]; every other shape
    /// (`host:…`, `anonymous:…`, bare operator ids) keeps the
    /// historical [`EditSource::Human`] default.
    #[must_use]
    pub fn default_for_agent_id(agent_id: &str) -> Self {
        if agent_id.starts_with(crate::identity::sentinels::AI_AGENT_ID_PREFIX) {
            Self::Agent
        } else {
            Self::Human
        }
    }

    /// `true` when the edit-source semantics call for the
    /// append-and-archive write path (vs. in-place mutation).
    #[must_use]
    pub fn appends_and_archives(&self) -> bool {
        matches!(self, Self::Llm | Self::Hook)
    }
}

/// v0.7.0 Form 4 (issue #757) — fact-provenance citation envelope.
///
/// One entry inside `Memory::citations`. The shape mirrors common
/// scholarly-citation needs while staying substrate-friendly:
///
/// * `uri` — URL, `doc:<id>` substrate pointer, or `file:<path>`. The
///   validator (`crate::validate::validate_citation`) rejects bare
///   strings; callers must use one of the typed schemes.
/// * `accessed_at` — RFC3339 timestamp at which the cited source was
///   read by the agent. Captures the fact-grain "when did this claim
///   become known to me" datum.
/// * `hash` — optional SHA-256 of the cited content. Lets a downstream
///   verifier confirm the source has not drifted since capture.
/// * `span` — optional byte-range pinning the specific quote inside
///   the cited body. Composes with `Memory::source_span` for
///   atom-grain lineage (the parent's span points into the source,
///   the atom's `source_span` points into the parent's body).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Citation {
    pub uri: String,
    pub accessed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<SourceSpan>,
}

/// v0.7.0 Form 4 (issue #757) — byte-range envelope used by
/// `Memory::source_span` and `Citation::span`.
///
/// `start` and `end` are zero-based byte offsets into the parent
/// body. The half-open convention `[start, end)` matches Rust's
/// slice semantics, so the cited slice is `body[start..end]`. The
/// validator (`crate::validate::validate_source_span`) requires
/// `start < end` and bounds both within `usize::MAX`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceSpan {
    pub start: usize,
    pub end: usize,
}

/// v0.7.0 Gap 4 (issue #887) — derived enum partitioning the
/// `confidence` real into operator-meaningful buckets so callers
/// (especially read-side reviewers) can filter by tier instead of
/// re-deriving thresholds at every site.
///
/// Thresholds are stable and load-bearing — operators have wired
/// dashboards / human-review queues against them and a change here
/// is a wire-level break. Bumping a threshold is therefore a
/// schema-bump-class decision, NOT a code-tuning decision.
///
/// - [`ConfidenceTier::Confirmed`] — `>= 0.95`. High-confidence
///   substrate-curated atoms, typically calibrated by the Form 5
///   pipeline or asserted by a trusted upstream.
/// - [`ConfidenceTier::Likely`] — `0.7 ..= 0.949…`. Default
///   caller-provided observations sit here.
/// - [`ConfidenceTier::Ambiguous`] — `< 0.7`. The human-review
///   queue: the caller themselves flagged uncertainty (or the
///   decay updater walked the value down). Operators commonly
///   filter their review tool against this tier.
///
/// Surfaced to MCP callers via the `confidence_calibration.tier_thresholds`
/// block on `memory_capabilities` (Gap 4 read-path closeout).
///
/// # Disambiguation (issue #970)
///
/// The codebase has three enums whose names end in `Tier`.
/// `ConfidenceTier` (this enum) is the **confidence-value bucket**;
/// it is unrelated to:
///
/// - [`Tier`] — memory-lifecycle TTL bucket (Short/Mid/Long).
/// - [`crate::config::FeatureTier`] — host capability tier
///   (Keyword/Semantic/Smart/Autonomous).
///
/// They do not share variants, wire strings, or call sites. See
/// `docs/internal/enum-proliferation-audit-970.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceTier {
    Confirmed,
    Likely,
    Ambiguous,
}

impl ConfidenceTier {
    /// Inclusive lower bound for [`ConfidenceTier::Confirmed`]. Above
    /// this is a high-confidence observation / calibration result.
    pub const CONFIRMED_MIN: f64 = 0.95;
    /// Inclusive lower bound for [`ConfidenceTier::Likely`]. Below
    /// this is the human-review tier ([`ConfidenceTier::Ambiguous`]).
    pub const LIKELY_MIN: f64 = 0.7;

    /// Bucket a raw confidence value. NaN is conservatively mapped
    /// to [`ConfidenceTier::Ambiguous`] so a corrupt input lands in
    /// the human-review queue rather than masquerading as confirmed.
    #[must_use]
    pub fn from_confidence(c: f64) -> Self {
        if c.is_nan() {
            return Self::Ambiguous;
        }
        if c >= Self::CONFIRMED_MIN {
            Self::Confirmed
        } else if c >= Self::LIKELY_MIN {
            Self::Likely
        } else {
            Self::Ambiguous
        }
    }

    /// Wire string for this tier. Matches the serde `rename_all =
    /// "snake_case"` derive above so the JSON and the unstructured
    /// helper agree.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Likely => "likely",
            Self::Ambiguous => "ambiguous",
        }
    }

    /// Parse a wire string back into the enum. Returns `None` on
    /// unrecognised input so callers can decide whether to error or
    /// fall through to "no filter".
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "confirmed" => Some(Self::Confirmed),
            "likely" => Some(Self::Likely),
            "ambiguous" => Some(Self::Ambiguous),
            _ => None,
        }
    }
}

impl Memory {
    /// v0.7.0 Gap 4 (#887) — derived [`ConfidenceTier`] for this
    /// memory's `confidence` value. Stable mapping; see
    /// [`ConfidenceTier::from_confidence`] for the thresholds.
    #[must_use]
    pub fn confidence_tier(&self) -> ConfidenceTier {
        ConfidenceTier::from_confidence(self.confidence)
    }
}

impl Default for Memory {
    /// All-zero / empty defaults. Useful as a base for ad-hoc test fixtures
    /// — `Memory { id: ..., title: ..., ..Default::default() }` — and for
    /// `#[serde(default)]` deserialisation of partial JSON. Tier defaults to
    /// `Mid` to match the API-layer default in [`CreateMemory`].
    fn default() -> Self {
        Self {
            cid: None, // v0.9.0 G8 (#1825) — stamped by db::insert / read via row_to_memory
            valid_from: None,
            valid_until: None,
            id: String::new(),
            tier: Tier::Mid,
            namespace: crate::DEFAULT_NAMESPACE.to_string(),
            title: String::new(),
            content: String::new(),
            tags: Vec::new(),
            priority: 5,
            confidence: DEFAULT_CONFIDENCE,
            source: "api".to_string(),
            access_count: 0,
            created_at: String::new(),
            updated_at: String::new(),
            last_accessed_at: None,
            expires_at: None,
            metadata: default_metadata(),
            reflection_depth: 0,
            memory_kind: MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: default_memory_version(),
            lifecycle_state: LifecycleState::Open,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateMemory {
    #[serde(default = "default_tier")]
    pub tier: Tier,
    #[serde(default = "default_namespace")]
    pub namespace: String,
    pub title: String,
    pub content: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_priority")]
    pub priority: i32,
    /// Confidence 0.0–1.0. `None` (caller omitted the field) resolves
    /// to [`DEFAULT_CONFIDENCE`] with truthful
    /// `confidence_source = "default"` provenance (#1591) via
    /// [`CreateMemory::resolved_confidence`] /
    /// [`CreateMemory::resolved_confidence_source`].
    #[serde(default)]
    pub confidence: Option<f64>,
    #[serde(default = "default_source")]
    pub source: String,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub ttl_secs: Option<i64>,
    #[serde(default = "default_metadata")]
    pub metadata: Value,
    /// Optional agent identifier. When unset, the server resolves a default
    /// via `crate::identity` (NHI-hardened precedence chain).
    #[serde(default)]
    pub agent_id: Option<String>,
    /// Optional visibility scope (Task 1.5). One of `VALID_SCOPES`. When
    /// unset, treated as `private` by the query layer.
    #[serde(default)]
    pub scope: Option<String>,
    /// v0.6.3.1 P2 (G6) — collision policy when (title, namespace) already
    /// exists. One of `error` | `merge` | `version`. When unset, the
    /// daemon defaults to `error` for HTTP callers (HTTP is not legacy
    /// like MCP v1; clients that want the legacy silent-merge contract
    /// must opt in explicitly).
    #[serde(default)]
    pub on_conflict: Option<String>,
    /// v0.7.0 (issue #519) — when `Some(true)`, run a proactive
    /// `detect_contradiction` LLM probe against same-namespace memories
    /// BEFORE returning 201, regardless of `autonomous_hooks`. When
    /// `Some(false)`, force-disable detection even if `autonomous_hooks`
    /// is on. When `None`, defer to `autonomous_hooks`.
    ///
    /// Surface: the 201 response body grows a `conflicts: [{...}]` array
    /// listing every same-namespace candidate the LLM flags as
    /// contradictory. Each entry carries the candidate id, title, and
    /// (when LLM produces one) a `suggested_merge` content string the
    /// caller can pass to a follow-up `memory_consolidate`.
    #[serde(default)]
    pub detect_conflicts: Option<bool>,
    /// v0.7.0 (issue #519) — proactive contradiction detection bypass.
    /// When `true`, the substrate-level `proactive_conflict_check` is
    /// skipped on this write so a near-duplicate-with-differing-content
    /// row is inserted anyway. Default `false` preserves the new v0.7.0
    /// refuse-by-default posture; callers that explicitly want the
    /// conflicting fact to land alongside the existing one set
    /// `force=true`.
    #[serde(default)]
    pub force: bool,
    /// v0.7.0 Form 4 (issue #757) — fact-provenance citations
    /// supplied at write time. Each entry must satisfy
    /// `validate::validate_citation`. Empty by default.
    #[serde(default)]
    pub citations: Vec<Citation>,
    /// v0.7.0 Form 4 — optional URI-form pointer to the cited source
    /// body. Must satisfy `validate::validate_source_uri` when set.
    #[serde(default)]
    pub source_uri: Option<String>,
    /// v0.7.0 Form 4 — optional byte-range into the parent source
    /// body. Must satisfy `validate::validate_source_span` when set.
    #[serde(default)]
    pub source_span: Option<SourceSpan>,
    /// v0.7.x Form 6 (#1385) — Batman-taxonomy memory-kind selector for
    /// the new row. Accepts any [`MemoryKind`] wire token
    /// (`observation` | `reflection` | `persona` | `concept` | `entity`
    /// | `claim` | `relation` | `event` | `conversation` | `decision`
    /// | `goal` | `plan` | `step`). Unknown values are silently
    /// ignored (treated as omission) for
    /// forward-compat with future variants, mirroring the MCP
    /// `memory_store` `params["kind"]` contract at
    /// `src/mcp/tools/store/validation.rs:207-213`. Absent / unknown
    /// → handler defaults to `MemoryKind::Observation`. Stored as
    /// `Option<String>` (not `Option<MemoryKind>`) so unknown future
    /// tokens deserialise without breaking the request envelope.
    ///
    /// Pre-#1385 this field did not exist on `CreateMemory`, so HTTP
    /// `POST /api/v1/memories` silently dropped the caller's `kind`
    /// and every HTTP-created row landed as `Observation`. The Form 6
    /// recall `kinds` filter then returned zero rows against HTTP-
    /// written data even when the caller had stored `kind: "claim"`
    /// (the v3 NHI assessment defect D-v3-3 reproducible against the
    /// alice lan-parity postgres-backed daemon).
    #[serde(default)]
    pub kind: Option<String>,
    /// #626 Layer-3 (C7) — detached Ed25519 agent-attestation signature,
    /// standard base64, over the `SignableWrite` envelope
    /// (`agent_id + namespace + title + kind + created_at +
    /// sha256(content)`). When present, `created_at` MUST also be supplied
    /// (the signer cannot predict the server clock); a signature that
    /// fails to verify against the agent's bound public key is rejected
    /// with 403. Absent ⇒ unsigned write, which the gate REJECTS under
    /// the v0.9 required-attestation default (#1751) unless the operator
    /// set the `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0` opt-out (in which
    /// case it lands `attest_level = "claimed"`).
    #[serde(default)]
    pub signature: Option<String>,
    /// #626 Layer-3 (C7) — RFC3339 timestamp the caller signed. Required
    /// when `signature` is present; the server validates it against the
    /// ±300s attestation freshness window and then adopts it verbatim so
    /// the verifier re-derives the identical signed envelope.
    #[serde(default)]
    pub created_at: Option<String>,
    /// #2258 / #1834 — claim-bitemporal VALID-time start. RFC3339 timestamp
    /// recording when the fact BECAME true (backfill / future-effective),
    /// distinct from `created_at` transaction-time. Validated via
    /// `validate::validate_valid_at`. IMMUTABLE after create — a later upsert
    /// keeps the stored value (`db::insert` / `PostgresStore::store` ON
    /// CONFLICT preserve `valid_from`). Absent ⇒ unbounded start.
    #[serde(default)]
    pub valid_from: Option<String>,
    /// #2258 / #1834 — claim-bitemporal VALID-time end bound (half-open
    /// `[valid_from, valid_until)`). RFC3339; validated via
    /// `validate::validate_valid_at`. Stays updatable via `PUT /memories/{id}`
    /// (`memory_update`). Absent ⇒ unbounded end.
    #[serde(default)]
    pub valid_until: Option<String>,
}

/// Compiled default `confidence` stamped when a store surface (MCP
/// `memory_store`, HTTP `POST /api/v1/memories`, CLI `ai-memory store`)
/// receives no explicit caller value. #1591 — rows minted from this
/// fallback carry `confidence_source = `[`ConfidenceSource::Default`]
/// instead of falsely claiming `caller_provided`.
pub const DEFAULT_CONFIDENCE: f64 = 1.0;

/// Lowest semantic `priority` a memory row may carry.
pub const PRIORITY_MIN: i32 = 1;

/// Highest semantic `priority` a memory row may carry.
pub const PRIORITY_MAX: i32 = 10;

/// Compiled default `priority` stamped when a surface receives no explicit
/// caller value.
pub const DEFAULT_PRIORITY: i32 = 5;

/// v1.0.0 batch-2 (cross-backend parity) — SSOT for turning a caller-supplied
/// wire `priority` (an `i64` on every JSON surface) into the stored `i32`.
///
/// Clamps in `i64` space FIRST, which makes the subsequent narrowing total:
/// the clamped value is always in `[PRIORITY_MIN, PRIORITY_MAX]`, so the
/// `TryFrom` can never fail and the `unwrap_or` is unreachable defence rather
/// than a behaviour (PERF-07 — the narrowing is explicit, never a silent `as`).
///
/// Saturation is DIRECTIONAL: a value below the band lands on the floor and a
/// value above it lands on the ceiling, for ANY magnitude. The prior inline
/// expression (`i32::try_from(raw).unwrap_or(i32::MAX).clamp(1, 10)`, in
/// `mcp::handle_notify`) saturated a value below `i32::MIN` UPWARD, so
/// `priority = i64::MIN` was stored as the MAXIMUM priority 10 — the exact
/// inversion of what the caller asked for. That is corrected here.
///
/// Pre-fix the HTTP `POST /api/v1/notify` sqlite branch clamped through
/// `mcp::handle_notify` while the postgres branch used
/// `i64 -> i32 try_from().ok()`, which (a) DROPPED an out-of-`i32` priority to
/// the default and (b) never clamped an in-`i32` but out-of-band value like
/// `50`. Identical requests therefore produced different durable rows
/// depending on the backend.
#[must_use]
pub fn normalize_priority(raw: i64) -> i32 {
    let clamped = raw.clamp(i64::from(PRIORITY_MIN), i64::from(PRIORITY_MAX));
    // Unreachable fallback: `clamped` is provably inside the i32 band above.
    i32::try_from(clamped).unwrap_or(DEFAULT_PRIORITY)
}

#[cfg(test)]
mod priority_normalization_tests {
    use super::{DEFAULT_PRIORITY, PRIORITY_MAX, PRIORITY_MIN, normalize_priority};

    #[test]
    fn in_band_values_pass_through() {
        for p in PRIORITY_MIN..=PRIORITY_MAX {
            assert_eq!(
                normalize_priority(i64::from(p)),
                p,
                "in-band priority {p} must pass through unchanged"
            );
        }
        assert_eq!(
            normalize_priority(i64::from(DEFAULT_PRIORITY)),
            DEFAULT_PRIORITY
        );
    }

    #[test]
    fn out_of_band_and_out_of_i32_saturate_to_the_band() {
        assert_eq!(
            normalize_priority(0),
            PRIORITY_MIN,
            "0 clamps up to the floor"
        );
        assert_eq!(
            normalize_priority(-9_000),
            PRIORITY_MIN,
            "negatives clamp to the floor"
        );
        assert_eq!(
            normalize_priority(50),
            PRIORITY_MAX,
            "in-i32 but out-of-band clamps down"
        );
        assert_eq!(
            normalize_priority(3_000_000_000),
            PRIORITY_MAX,
            "an i64 beyond i32::MAX saturates to the ceiling, never drops to the default"
        );
        // DIRECTIONAL saturation at the extremes. The pre-SSOT inline
        // expression saturated `i64::MIN` UPWARD to the ceiling (10) — a
        // hugely NEGATIVE caller priority became the HIGHEST priority.
        assert_eq!(
            normalize_priority(i64::MIN),
            PRIORITY_MIN,
            "a value below the band must land on the FLOOR, never invert to the ceiling"
        );
        assert_eq!(normalize_priority(i64::MAX), PRIORITY_MAX);
    }
}

impl CreateMemory {
    /// #1591 — effective confidence for this request: the caller's
    /// explicit value, else the compiled [`DEFAULT_CONFIDENCE`].
    #[must_use]
    pub fn resolved_confidence(&self) -> f64 {
        self.confidence.unwrap_or(DEFAULT_CONFIDENCE)
    }

    /// #1591 — truthful confidence provenance for this request:
    /// [`ConfidenceSource::CallerProvided`] only when the caller
    /// actually sent a `confidence` value;
    /// [`ConfidenceSource::Default`] when the compiled fallback was
    /// stamped.
    #[must_use]
    pub fn resolved_confidence_source(&self) -> ConfidenceSource {
        if self.confidence.is_some() {
            ConfidenceSource::CallerProvided
        } else {
            ConfidenceSource::Default
        }
    }
}

fn default_tier() -> Tier {
    Tier::Mid
}
fn default_namespace() -> String {
    // #1590 — honour the operator-configured `[storage].default_namespace`
    // (seeded process-wide at boot from `AppConfig::resolve_storage`) on
    // the HTTP store surface; unconfigured deployments keep the
    // historical compiled default.
    crate::config::configured_default_namespace()
        .unwrap_or_else(|| crate::DEFAULT_NAMESPACE.to_string())
}
fn default_priority() -> i32 {
    5
}
fn default_source() -> String {
    "api".to_string()
}

#[derive(Debug, Deserialize)]
pub struct UpdateMemory {
    pub title: Option<String>,
    pub content: Option<String>,
    pub tier: Option<Tier>,
    pub namespace: Option<String>,
    pub tags: Option<Vec<String>>,
    pub priority: Option<i32>,
    pub confidence: Option<f64>,
    pub expires_at: Option<String>,
    pub metadata: Option<Value>,
    /// v0.7.0 Provenance Gap 2 (#906) — opt-in `source_uri` patch.
    /// `None` leaves the stored value alone (COALESCE on the SQL
    /// layer); `Some("scheme:payload")` rewrites the row's source_uri
    /// (doc rename / URI scheme migration / bad-data correction).
    /// Validated by `validate::validate_source_uri` before reaching
    /// storage.
    pub source_uri: Option<String>,
    /// v1.0.0 #1834 — opt-in claim-bitemporal `valid_until` patch. `None`
    /// leaves the stored value alone (COALESCE at the SQL layer); `Some(v)`
    /// closes or moves the claim's VALID interval. `valid_from` is IMMUTABLE
    /// (the genesis assertion instant) and is deliberately absent from this
    /// patch — it is never updatable. Validated by `validate::validate_valid_at`
    /// before reaching storage.
    #[serde(default)]
    pub valid_until: Option<String>,
    /// v0.7.0 #930 SECURITY-high (Track A P9, 2026-05-20) — optional
    /// caller-asserted `agent_id` for body/header parity. When set,
    /// MUST match the resolved `X-Agent-Id` header (Full-Measure-A
    /// posture). Mismatch → HTTP 403. Pre-fix the sqlite UPDATE path
    /// silently accepted ANY body.agent_id (or none) and never gated
    /// the writer against the row's recorded owner — enabling
    /// cross-tenant write hijack with forged provenance.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// v0.8.0 Pillar 2 (#1726) — opt-in lifecycle transition target
    /// (`open` / `active` / `blocked` / `done` / `abandoned`). `None` leaves
    /// the stored `lifecycle_state` untouched; a supplied value is validated
    /// (`validate_lifecycle_state`) and the transition legality is enforced
    /// against the stored state (`LifecycleState::can_transition_to`) in the
    /// update path — an illegal edge returns HTTP 409, a legal one persists
    /// and bumps the optimistic-concurrency `version`. A request equal to the
    /// stored state is an idempotent no-op.
    #[serde(default)]
    pub lifecycle_state: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    /// FTS query string. v0.7.0 Provenance Gap 6 (#889/#891): may be
    /// empty when `source_uri` is supplied (reciprocal source-only
    /// query). Handler rejects only when BOTH are empty.
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub tier: Option<Tier>,
    #[serde(default = "default_limit")]
    pub limit: Option<usize>,
    #[serde(default)]
    pub min_priority: Option<i32>,
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default)]
    pub until: Option<String>,
    #[serde(default)]
    pub tags: Option<String>, // comma-separated
    /// Filter by `metadata.agent_id` (exact match).
    #[serde(default)]
    pub agent_id: Option<String>,
    /// Task 1.5 visibility: the querying agent's namespace position.
    /// When set, results are filtered per `metadata.scope` rules.
    #[serde(default)]
    pub as_agent: Option<String>,
    /// v0.7.0 Provenance Gap 6 (#889) — reciprocal source filter.
    /// When `source_uri=X` is supplied, the result set is narrowed
    /// to memories whose `source_uri` column equals X verbatim. The
    /// partial `idx_memories_source_uri` index (v38) covers the
    /// lookup so the query is O(log N).
    #[serde(default)]
    pub source_uri: Option<String>,
    /// #1579 B4 — response format negotiation: `json` (default) |
    /// `toon` | `toon_compact`. Reuses the MCP TOON encoder
    /// (`crate::toon`); invalid values are rejected with `400`
    /// carrying the SSOT message from
    /// `crate::toon::invalid_format_msg`.
    #[serde(default)]
    pub format: Option<String>,
}

#[allow(clippy::unnecessary_wraps)]
fn default_limit() -> Option<usize> {
    Some(20)
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub tier: Option<Tier>,
    #[serde(default = "default_limit")]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default)]
    pub min_priority: Option<i32>,
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default)]
    pub until: Option<String>,
    /// v1.0.0 #1834 — claim-bitemporal AS-OF: RFC3339 point in VALID-time.
    /// Returns only claims asserted to hold at this instant (their half-open
    /// `[valid_from, valid_until)` window contains it). Omit for no filter.
    #[serde(default)]
    pub valid_at: Option<String>,
    #[serde(default)]
    pub tags: Option<String>,
    /// Filter by `metadata.agent_id` (exact match).
    #[serde(default)]
    pub agent_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RecallQuery {
    pub context: Option<String>,
    /// `query` alias for `context` — the cert harness (S79) uses
    /// `?query=…`. Both forms route to the same code path; `context`
    /// wins when both are supplied.
    #[serde(default)]
    pub query: Option<String>,
    /// `q` alias for `context`/`query` — matches the search-style API
    /// surface (`/api/v1/memories?q=…`) so callers can use the same
    /// query token field across both endpoints.
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default = "default_recall_limit")]
    pub limit: Option<usize>,
    #[serde(default)]
    pub tags: Option<String>,
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default)]
    pub until: Option<String>,
    /// #1834 claim-bitemporal as-of: RFC3339 point in valid-time.
    #[serde(default)]
    pub valid_at: Option<String>,
    /// Task 1.5 visibility filtering.
    #[serde(default)]
    pub as_agent: Option<String>,
    /// Task 1.11 — context-budget-aware recall. When set, return the
    /// top-scored memories whose cumulative estimated tokens fit within
    /// this budget.
    #[serde(default)]
    pub budget_tokens: Option<usize>,
    /// #1622 — salience tokens biasing the recall query embedding,
    /// comma-separated (`context_tokens=alpha,beta`), mirroring the
    /// `kinds` CSV convention for GET query params.
    #[serde(default)]
    pub context_tokens: Option<String>,
    /// v0.7.0 (issue #518) — when `true`, splice defaults from
    /// `[agents.defaults.recall_scope]` in `config.toml` for any
    /// filter field not explicitly set on this request. Resolution:
    /// explicit args > recall_scope defaults > compiled defaults.
    /// Default `false` preserves v0.6.x recall semantics exactly.
    #[serde(default)]
    pub session_default: Option<bool>,
    /// v0.7.0 Form 4 (issue #757) — restrict to memories whose
    /// `citations` array is non-empty. Composes with the other
    /// filters; default `None` preserves v0.7.0 recall semantics.
    #[serde(default)]
    pub has_citations: Option<bool>,
    /// v0.7.0 Form 4 (issue #757) — restrict to memories whose
    /// `source_uri` column begins with this exact prefix.
    #[serde(default)]
    pub source_uri_prefix: Option<String>,
    /// v0.7.x Form 6 (issue #759) — Batman-taxonomy memory-kind
    /// filter. Comma-separated string (`kinds=concept,claim`).
    /// OR-of-kinds within the param; AND with namespace / tags /
    /// time-window / visibility. `None` (default) preserves the
    /// pre-Form-6 "no kind filter" semantics. Unknown tokens are
    /// silently dropped (forward-compat with future variants).
    #[serde(default)]
    pub kinds: Option<String>,
    /// v0.7.0 (issue #518) — per-session "recently accessed" boost.
    /// When set and non-empty, the rerank post-step adds +0.05 to any
    /// recall candidate already in this session's ring buffer (cap
    /// 50 ids, FIFO eviction); the recall hit set is appended to the
    /// ring so subsequent recalls in the same session reuse the new
    /// context. `None`/empty preserves pre-#518 recall semantics
    /// exactly.
    #[serde(default)]
    pub session_id: Option<String>,
    /// v0.7.0 #1098 — WT-1-E include atomised sources alongside atoms.
    /// HTTP parity with the MCP `RecallRequest`. Pre-#1098 this field
    /// was hard-coded to `None` in `RecallRequest::from_http_query`.
    #[serde(default)]
    pub include_archived: Option<bool>,
    /// v0.7.0 #1098 — Gap 4 (#887) confidence-tier filter. HTTP
    /// parity with the MCP `RecallRequest`.
    #[serde(default)]
    pub confidence_tier: Option<String>,
    /// v0.7.0 #1098 — Gap 7 (#890) per-row provenance decoration.
    /// HTTP parity with the MCP `RecallRequest`.
    #[serde(default)]
    pub verbose_provenance: Option<bool>,
    /// v0.7.0 #1098 — response format selector (e.g. `toon_compact`).
    /// HTTP parity with the MCP `RecallRequest`.
    #[serde(default)]
    pub format: Option<String>,
}

#[allow(clippy::unnecessary_wraps)]
fn default_recall_limit() -> Option<usize> {
    Some(10)
}

#[derive(Debug, Deserialize)]
pub struct RecallBody {
    /// Recall context. Accepts either `context` (canonical), `query`
    /// (cert harness alias used by S79), or `q` (matches the
    /// search-style API surface). At least one must be present and
    /// non-empty.
    #[serde(default)]
    pub context: Option<String>,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default = "default_recall_limit")]
    pub limit: Option<usize>,
    #[serde(default)]
    pub tags: Option<String>,
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default)]
    pub until: Option<String>,
    /// #1834 claim-bitemporal as-of: RFC3339 point in valid-time.
    #[serde(default)]
    pub valid_at: Option<String>,
    /// Task 1.5 visibility filtering.
    #[serde(default)]
    pub as_agent: Option<String>,
    /// Task 1.11 — context-budget-aware recall.
    #[serde(default)]
    pub budget_tokens: Option<usize>,
    /// #1622 — salience tokens biasing the recall query embedding
    /// (70/30 blend). Pre-#1622 this field was unreachable from HTTP
    /// (hard-coded `None` in `from_http_body`) while MCP + CLI honored
    /// it — the same class #1098 fixed for four other fields.
    #[serde(default)]
    pub context_tokens: Option<Vec<String>>,
    /// v0.7.0 (issue #518) — when `true`, splice defaults from
    /// `[agents.defaults.recall_scope]` in `config.toml` for any
    /// filter field not explicitly set on this request body.
    /// Resolution: explicit args > recall_scope defaults > compiled
    /// defaults. Default `false` preserves v0.6.x recall semantics.
    #[serde(default)]
    pub session_default: Option<bool>,
    /// v0.7.0 Form 4 (issue #757) — restrict to memories whose
    /// `citations` array is non-empty. Composes with the other
    /// filters.
    #[serde(default)]
    pub has_citations: Option<bool>,
    /// v0.7.0 Form 4 (issue #757) — restrict to memories whose
    /// `source_uri` column begins with this exact prefix.
    #[serde(default)]
    pub source_uri_prefix: Option<String>,
    /// v0.7.x Form 6 (issue #759) — Batman-taxonomy memory-kind
    /// filter. Accepts either a JSON array of strings
    /// (`{"kinds": ["concept", "claim"]}`) or a comma-separated
    /// string (`{"kinds": "concept,claim"}`). OR-of-kinds within
    /// the param; AND with the other filters.
    #[serde(default)]
    pub kinds: Option<serde_json::Value>,
    /// v0.7.0 (issue #518) — per-session recency boost. See the
    /// matching field on [`RecallQuery`].
    #[serde(default)]
    pub session_id: Option<String>,
    /// v0.7.0 #1098 — WT-1-E include atomised sources alongside
    /// atoms. HTTP parity with the MCP `RecallRequest`.
    #[serde(default)]
    pub include_archived: Option<bool>,
    /// v0.7.0 #1098 — Gap 4 (#887) confidence-tier filter. HTTP
    /// parity with the MCP `RecallRequest`.
    #[serde(default)]
    pub confidence_tier: Option<String>,
    /// v0.7.0 #1098 — Gap 7 (#890) per-row provenance decoration.
    /// HTTP parity with the MCP `RecallRequest`.
    #[serde(default)]
    pub verbose_provenance: Option<bool>,
    /// v0.7.0 #1098 — response format selector (e.g. `toon_compact`).
    /// HTTP parity with the MCP `RecallRequest`.
    #[serde(default)]
    pub format: Option<String>,
}

impl RecallBody {
    /// Resolve the recall query string from `context`, `query`, or `q`.
    /// Returns the trimmed value, or an empty string when all three are
    /// absent — the caller is expected to reject empty.
    #[must_use]
    pub fn resolved_query(&self) -> String {
        self.context
            .as_deref()
            .or(self.query.as_deref())
            .or(self.q.as_deref())
            .unwrap_or("")
            .trim()
            .to_string()
    }

    /// v0.7.x Form 6 — parse the optional `kinds` JSON field.
    /// Accepts a JSON array of strings or a single comma-separated
    /// string. Treats `"all"` as "no filter" (returns `None`).
    /// Drops unknown tokens silently.
    ///
    /// Cluster E audit COR-4 (issue #767): mirrors
    /// [`MemoryKind::parse_csv`] semantics — an explicit array of
    /// only-unknown tokens (e.g. `["reflektion"]`) returns
    /// `Some(vec![])` (intentional zero-match filter), distinct from
    /// the absent / empty / `"all"` cases which return `None`
    /// (no filter declared).
    #[must_use]
    pub fn resolved_kinds(&self) -> Option<Vec<MemoryKind>> {
        let raw = self.kinds.as_ref()?;
        if let Some(s) = raw.as_str() {
            if s.trim().eq_ignore_ascii_case("all") {
                return None;
            }
            return MemoryKind::parse_csv(s);
        }
        if let Some(arr) = raw.as_array() {
            // Empty JSON array → no filter declared (matches the
            // CSV "" case in parse_csv).
            if arr.is_empty() {
                return None;
            }
            let mut out: Vec<MemoryKind> = Vec::new();
            for v in arr {
                if let Some(name) = v.as_str()
                    && let Some(k) = MemoryKind::from_str(name.trim())
                    && !out.contains(&k)
                {
                    out.push(k);
                }
            }
            // Non-empty array (even if every entry was unknown)
            // returns Some(out); collapsing to None would silently
            // invert a typo'd filter into "match all" (COR-4 bug).
            Some(out)
        } else {
            None
        }
    }
}

impl RecallQuery {
    /// v0.7.x Form 6 — parse the optional `kinds` query string.
    /// Comma-separated. `"all"` (case-insensitive) is treated as "no
    /// filter" (returns `None`). Drops unknown tokens silently.
    #[must_use]
    pub fn resolved_kinds(&self) -> Option<Vec<MemoryKind>> {
        let s = self.kinds.as_deref()?;
        if s.trim().eq_ignore_ascii_case("all") {
            return None;
        }
        MemoryKind::parse_csv(s)
    }
}

#[derive(Debug, Deserialize)]
pub struct ForgetQuery {
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub pattern: Option<String>, // FTS pattern
    #[serde(default)]
    pub tier: Option<Tier>,
}

/// v0.6.3.1 (P3): per-request observability for the recall pipeline.
///
/// Surfaces *which* recall path actually ran, *which* reranker was active,
/// the candidate pool sizes coming out of FTS and HNSW (before fusion), and
/// the blend weight applied to the semantic component. Always present in
/// `memory_recall` responses; older clients ignore unknown fields per the
/// JSON-RPC convention.
///
/// Closes G2/G8/G11 from the v0.6.3 audit by making every silent-degrade
/// path observable at request time. The capabilities surface (P1) reports
/// the same state at startup; this struct is the per-call mirror.
#[derive(Debug, Clone, Serialize)]
pub struct RecallMeta {
    /// Which recall path executed.
    /// - `"hybrid"` — embedder + FTS, blended (G11 happy path).
    /// - `"keyword_only"` — embedder unavailable or query-embed failed,
    ///   keyword-only recall served (G11 silent-degrade now visible).
    pub recall_mode: String,
    /// Which reranker scored the final ordering.
    /// - `"neural"` — BERT cross-encoder (autonomous tier, model loaded).
    /// - `"lexical"` — operator opted for the lexical variant, or the
    ///   tier never asked for a neural cross-encoder.
    /// - `"degraded_lexical"` — v0.7.0 R3-S2 — a configured neural
    ///   cross-encoder failed to initialise or errored mid-flight and
    ///   the runtime fell back. Distinct from `"lexical"` so clients
    ///   can detect the silent downgrade *in band* (previously this
    ///   was only a `tracing::warn!` event, which the G8 closure
    ///   claim overstated as "fail loud").
    /// - `"none"` — reranking disabled at this tier.
    pub reranker_used: String,
    /// Candidate-pool sizes coming out of each retrieval stage *before*
    /// fusion. Useful for spotting empty-FTS or empty-HNSW degradations.
    pub candidate_counts: CandidateCounts,
    /// Semantic blend weight applied during fusion. `0.0` for
    /// `keyword_only` mode; otherwise the average semantic weight across
    /// the returned candidates (varies 0.50→0.15 with content length).
    pub blend_weight: f64,
    /// v1.0.0 F-L8a (#2167 follow-up) — rows WITHHELD from SEMANTIC
    /// scoring this query because their stored vector could not be
    /// safely compared against the live query vector: a foreign VERIFIED
    /// space, an UNVERIFIED (`embedding_space IS NULL`) space, or a
    /// dimensionality mismatch. Such rows stay KEYWORD-recallable
    /// (degraded, never invisible) — their semantic cosine was forced to
    /// `0.0` and excluded from the ranking. The correctness danger is
    /// already CLOSED (a foreign/unverified vector is never scored); this
    /// block is the missing IN-BAND signal that `mode:"hybrid"` served
    /// fewer semantically-scored rows than the corpus holds. A JSON-only
    /// MCP-stdio NHI has no `/metrics`, so the daemon's tracing WARN is
    /// invisible to it — this block is the only introspectable channel.
    /// `mode` is UNCHANGED (still `"hybrid"`); this is additive.
    pub semantic_withheld: SemanticWithheld,
}

/// v0.6.3.1 (P3): retrieval-stage candidate counts feeding `RecallMeta`.
#[derive(Debug, Clone, Serialize)]
pub struct CandidateCounts {
    /// Number of candidates retrieved by FTS5 keyword scoring.
    pub fts: usize,
    /// Number of candidates retrieved by HNSW (or linear-scan fallback)
    /// semantic search. `0` in keyword-only mode.
    pub hnsw: usize,
}

/// v1.0.0 F-L8a (#2167 follow-up) — per-query breakdown of rows withheld
/// from SEMANTIC scoring, populated from the ALREADY-computed
/// [`RecallTelemetry`] counters (never recomputed). See
/// [`RecallMeta::semantic_withheld`].
///
/// **Honesty contract (North Star: DEGRADE, never report a WRONG value).**
/// `measured` distinguishes a path that COUNTS per-query exclusions from
/// one that does not:
/// - On a MEASURED recall path (the sqlite MCP / HTTP / CLI recall funnels
///   that thread [`RecallTelemetry`]) `measured` is `true` and the three
///   cause counters + `total` are present — an explicit `0` here is a
///   TRUTHFUL "nothing withheld".
/// - On an UNMEASURED path (the postgres SAL `recall_hybrid`, which
///   excludes foreign-space rows in SQL via `AND embedding_space = $fp`
///   but never counts them) `measured` is `false` and the numeric fields
///   are OMITTED rather than fabricated as `0` — emitting `0` where rows
///   were excluded uncounted would be a wrong result on the wire, the
///   exact failure this signal exists to prevent. Postgres per-query
///   counting is tracked as a follow-up.
#[derive(Debug, Clone, Serialize)]
pub struct SemanticWithheld {
    /// `true` when this recall path counts per-query exclusions and the
    /// numeric fields below are authoritative; `false` on a backend that
    /// excludes foreign-space rows without counting them (postgres SAL),
    /// where the numeric fields are absent.
    pub measured: bool,
    /// #2167 — rows VERIFIED in a DIFFERENT embedding space than the
    /// active embedder's fingerprint (a same-dim model swap the dim gate
    /// cannot catch). Absent on an unmeasured path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_mismatch: Option<usize>,
    /// #2167 — rows with NO provenance token (`embedding_space IS NULL`)
    /// or an ANN hit whose row-side vector could not be re-verified.
    /// Absent on an unmeasured path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unverified_space: Option<usize>,
    /// v0.7.0 H7 — rows whose stored embedding dimensionality disagreed
    /// with the active embedder model. Absent on an unmeasured path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dim_mismatch: Option<usize>,
    /// Convenience sum of the three causes above. Absent on an unmeasured
    /// path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
}

impl SemanticWithheld {
    /// Build the MEASURED block from the already-computed recall
    /// telemetry counters. Used by every sqlite recall funnel (MCP / HTTP
    /// / CLI); a keyword-only recall passes a zeroed [`RecallTelemetry`],
    /// which is a truthful "no semantic scoring ran, nothing withheld".
    #[must_use]
    pub fn measured(telemetry: &RecallTelemetry) -> Self {
        let total = telemetry.embedding_space_mismatch
            + telemetry.embedding_unverified_space
            + telemetry.embedding_dim_mismatch;
        Self {
            measured: true,
            space_mismatch: Some(telemetry.embedding_space_mismatch),
            unverified_space: Some(telemetry.embedding_unverified_space),
            dim_mismatch: Some(telemetry.embedding_dim_mismatch),
            total: Some(total),
        }
    }

    /// Build the UNMEASURED block for a backend that excludes foreign-space
    /// rows without counting them (the postgres SAL recall path). The
    /// numeric fields are omitted so a consumer never mistakes an
    /// uncounted exclusion for a measured zero.
    #[must_use]
    pub fn unmeasured() -> Self {
        Self {
            measured: false,
            space_mismatch: None,
            unverified_space: None,
            dim_mismatch: None,
            total: None,
        }
    }
}

/// v0.6.3.1 (P3): internal telemetry returned alongside recall results.
///
/// Plumbed from `db::recall_hybrid_with_telemetry` /
/// `db::recall_with_telemetry` up to `mcp::handle_recall`, which uses it
/// to populate `RecallMeta`. Not serialized — `RecallMeta` is the public
/// shape.
#[derive(Debug, Clone, Default)]
pub struct RecallTelemetry {
    /// Candidates returned by the FTS5 stage before fusion.
    pub fts_candidates: usize,
    /// Candidates returned by the HNSW (or linear-scan fallback) stage
    /// before fusion. `0` for keyword-only recall.
    pub hnsw_candidates: usize,
    /// Average semantic blend weight applied across the returned set.
    /// `0.0` for keyword-only recall.
    pub blend_weight_avg: f64,
    /// v0.7.0 H7 — count of stored embeddings whose dimensionality
    /// disagreed with the active embedder model during this recall, so
    /// their semantic signal was forced to `0.0` and excluded from the
    /// ranking. `0` in steady state; non-zero means the embedder model
    /// changed and the affected rows need re-embedding. The recall path
    /// also emits one aggregated `warn!` per query when this is non-zero.
    pub embedding_dim_mismatch: usize,
    /// v1.0.0 #2167 — count of stored embeddings VERIFIED in a DIFFERENT
    /// embedding space than the active embedder's fingerprint during this
    /// recall (a same-dim model swap the dim gate cannot catch). Excluded
    /// from semantic scoring (kept keyword-recallable). `0` in the
    /// homogeneous steady state; non-zero means a foreign-space corpus
    /// that `ai-memory reembed` heals.
    pub embedding_space_mismatch: usize,
    /// v1.0.0 #2167 — count of stored embeddings with NO provenance token
    /// (`embedding_space IS NULL` post-adoption, or an ANN hit whose
    /// row-side vector could not be re-verified) excluded from semantic
    /// scoring this recall. `0` after a clean boot adoption (§5).
    pub embedding_unverified_space: usize,
}

#[derive(Debug, Serialize)]
pub struct Stats {
    /// RAW physical row count (`COUNT(*)`), INCLUDING rows that are
    /// expired-awaiting-GC and lifecycle-hidden (tombstoned/quarantined).
    /// v1.0.0 #2334 (FBL-15): documented as the physical count; agents
    /// reconciling against boot's `total_memories` (a LIVE count) should
    /// read [`Stats::live`] instead — the two surfaces previously
    /// disagreed silently on the expiry axis.
    pub total: usize,
    /// v1.0.0 #2334 (FBL-15) — LIVE row count: non-expired
    /// (`expires_at IS NULL OR expires_at > now`) AND lifecycle-visible
    /// (the fail-closed [`lifecycle_visible_clause`] allow-list) — the
    /// same definition the boot inventory and `export_all` use. Additive
    /// wire field.
    #[serde(default)]
    pub live: usize,
    /// v1.0.0 #2334 (FBL-15) — rows past their `expires_at` still awaiting
    /// the next GC tick (up to 30 min in daemon topologies; indefinitely
    /// in CLI-only topologies between manual `ai-memory gc` runs). The
    /// expiry-axis remainder that made `total` and boot's live count
    /// diverge. Additive wire field.
    #[serde(default)]
    pub expired_pending_gc: usize,
    pub by_tier: Vec<TierCount>,
    pub by_namespace: Vec<NamespaceCount>,
    pub expiring_soon: usize,
    pub links_count: usize,
    pub db_size_bytes: u64,
    /// v0.6.3.1 P2 (G4) — count of rows whose stored `embedding_dim`
    /// disagrees with the BLOB length (or whose column is missing while
    /// a BLOB exists). 0 on a fresh database; non-zero indicates legacy
    /// rows the operator should re-embed. Consumed by the P7 doctor.
    #[serde(default)]
    pub dim_violations: u64,
    /// v0.6.3.1 (P3, G2): cumulative HNSW oldest-eviction count since this
    /// process started. Non-zero indicates the in-memory vector index has
    /// hit its `MAX_ENTRIES` cap and silently dropped older embeddings —
    /// recall quality may have degraded for evicted ids. Process-local
    /// (not persisted) because the index itself is process-local.
    #[serde(default)]
    pub index_evictions_total: u64,
}

#[derive(Debug, Serialize)]
pub struct TierCount {
    pub tier: String,
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct NamespaceCount {
    pub namespace: String,
    pub count: usize,
}

// -----------------------------------------------------------------
// L0.7-2 Tier A — memory.rs unit coverage
// Covers serde defaults (default_tier/default_namespace/etc.), Tier
// ↔ string round-trips, Memory::default, Tier::default_ttl_secs,
// RecallBody::resolved_query precedence.
// -----------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_round_trips_strings() {
        for (s, v) in [
            ("short", Tier::Short),
            ("mid", Tier::Mid),
            ("long", Tier::Long),
        ] {
            assert_eq!(Tier::from_str(s), Some(v.clone()));
            assert_eq!(v.as_str(), s);
            assert_eq!(format!("{v}"), s);
        }
    }

    #[test]
    fn tier_from_str_returns_none_for_unknown() {
        assert_eq!(Tier::from_str("unknown"), None);
        assert_eq!(Tier::from_str(""), None);
        assert_eq!(Tier::from_str("SHORT"), None); // case-sensitive
    }

    #[test]
    fn tier_default_ttl_secs_short_is_six_hours() {
        assert_eq!(
            Tier::Short.default_ttl_secs(),
            Some(6 * crate::SECS_PER_HOUR)
        );
    }

    #[test]
    fn tier_default_ttl_secs_mid_is_seven_days() {
        assert_eq!(Tier::Mid.default_ttl_secs(), Some(crate::SECS_PER_WEEK));
    }

    #[test]
    fn tier_default_ttl_secs_long_is_none() {
        assert_eq!(Tier::Long.default_ttl_secs(), None);
    }

    #[test]
    fn tier_rank_orders_short_mid_long() {
        assert!(Tier::Short.rank() < Tier::Mid.rank());
        assert!(Tier::Mid.rank() < Tier::Long.rank());
    }

    // #1466 — `effective_expires_at` is the single SSOT backfill used by
    // every store path. These pin the immortal-row regression: a non-Long
    // memory with `expires_at: None` must come back stamped at
    // `created_at + Tier::default_ttl_secs()`, Long stays None, and an
    // explicit value is preserved verbatim.

    #[test]
    fn effective_expires_at_backfills_mid_at_created_plus_one_week() {
        let mut m = Memory::default();
        m.tier = Tier::Mid;
        m.created_at = "2026-01-01T00:00:00+00:00".to_string();
        m.expires_at = None;
        let got = m.effective_expires_at().expect("mid must backfill");
        let parsed = chrono::DateTime::parse_from_rfc3339(&got).unwrap();
        let base = chrono::DateTime::parse_from_rfc3339(&m.created_at).unwrap();
        assert_eq!(
            (parsed - base).num_seconds(),
            crate::SECS_PER_WEEK,
            "mid backfill must equal created_at + SECS_PER_WEEK"
        );
    }

    #[test]
    fn effective_expires_at_backfills_short_at_created_plus_six_hours() {
        let mut m = Memory::default();
        m.tier = Tier::Short;
        m.created_at = "2026-01-01T00:00:00+00:00".to_string();
        m.expires_at = None;
        let got = m.effective_expires_at().expect("short must backfill");
        let parsed = chrono::DateTime::parse_from_rfc3339(&got).unwrap();
        let base = chrono::DateTime::parse_from_rfc3339(&m.created_at).unwrap();
        assert_eq!(
            (parsed - base).num_seconds(),
            6 * crate::SECS_PER_HOUR,
            "short backfill must equal created_at + 6h"
        );
    }

    #[test]
    fn effective_expires_at_long_stays_none() {
        let mut m = Memory::default();
        m.tier = Tier::Long;
        m.created_at = "2026-01-01T00:00:00+00:00".to_string();
        m.expires_at = None;
        assert_eq!(
            m.effective_expires_at(),
            None,
            "long has no TTL — must stay immortal"
        );
    }

    #[test]
    fn effective_expires_at_preserves_explicit_value() {
        let explicit = "2027-06-15T12:00:00+00:00".to_string();
        for tier in [Tier::Short, Tier::Mid, Tier::Long] {
            let mut m = Memory::default();
            m.tier = tier;
            m.created_at = "2026-01-01T00:00:00+00:00".to_string();
            m.expires_at = Some(explicit.clone());
            assert_eq!(
                m.effective_expires_at(),
                Some(explicit.clone()),
                "an explicit expiry must win over the tier default"
            );
        }
    }

    #[test]
    fn effective_expires_at_output_is_rfc3339_for_lexical_gc_compare() {
        // gc() compares `expires_at < now` as rfc3339 STRINGS, so the
        // backfill must emit the same `...THH:MM:SS+00:00` shape
        // `Utc::now().to_rfc3339()` produces — never a space-separated
        // SQLite datetime() form (which would sort wrong).
        let mut m = Memory::default();
        m.tier = Tier::Mid;
        m.created_at = "2026-01-01T00:00:00+00:00".to_string();
        m.expires_at = None;
        let got = m.effective_expires_at().unwrap();
        assert!(got.contains('T'), "must be ISO 'T'-separated: {got}");
        assert!(!got.contains(' '), "must not contain a space: {got}");
        assert!(
            chrono::DateTime::parse_from_rfc3339(&got).is_ok(),
            "must round-trip through rfc3339 parse: {got}"
        );
    }

    #[test]
    fn tier_serializes_to_snake_case() {
        let v = serde_json::to_value(Tier::Short).unwrap();
        assert_eq!(v, serde_json::Value::String("short".to_string()));
        let v = serde_json::to_value(Tier::Mid).unwrap();
        assert_eq!(v, serde_json::Value::String("mid".to_string()));
        let v = serde_json::to_value(Tier::Long).unwrap();
        assert_eq!(v, serde_json::Value::String("long".to_string()));
    }

    #[test]
    fn memory_default_uses_mid_tier_and_global_namespace() {
        let m = Memory::default();
        assert_eq!(m.tier, Tier::Mid);
        assert_eq!(m.namespace, "global");
        assert_eq!(m.priority, 5);
        assert!((m.confidence - 1.0).abs() < f64::EPSILON);
        assert_eq!(m.source, "api");
        assert_eq!(m.access_count, 0);
        assert_eq!(m.reflection_depth, 0);
        assert!(m.last_accessed_at.is_none());
        assert!(m.expires_at.is_none());
    }

    #[test]
    fn memory_round_trips_through_serde_with_reflection_depth() {
        let mut m = Memory::default();
        m.id = "mem-1".to_string();
        m.title = "test".to_string();
        m.content = "body".to_string();
        m.created_at = "2026-01-01T00:00:00Z".to_string();
        m.updated_at = "2026-01-01T00:00:00Z".to_string();
        m.reflection_depth = 3;
        let s = serde_json::to_string(&m).unwrap();
        let back: Memory = serde_json::from_str(&s).unwrap();
        assert_eq!(back.id, "mem-1");
        assert_eq!(back.reflection_depth, 3);
    }

    #[test]
    fn memory_deserialises_pre_v070_payload_without_reflection_depth() {
        // Pre-v0.7.0 payloads have no reflection_depth field. serde
        // default must populate it as 0.
        let json = serde_json::json!({
            "id": "old-mem",
            "tier": Tier::Mid.as_str(),
            "namespace": "ns",
            "title": "t",
            "content": "c",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "api",
            "access_count": 0,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
            "metadata": {},
        });
        let m: Memory = serde_json::from_value(json).unwrap();
        assert_eq!(m.reflection_depth, 0);
    }

    fn cm_minimal() -> serde_json::Value {
        serde_json::json!({
            "title": "t",
            "content": "c",
        })
    }

    #[test]
    fn create_memory_defaults_tier_to_mid() {
        // Lines 175-177: default_tier returns Tier::Mid via #[serde(default)].
        let cm: CreateMemory = serde_json::from_value(cm_minimal()).unwrap();
        assert_eq!(cm.tier, Tier::Mid);
    }

    #[test]
    fn create_memory_defaults_namespace_to_global() {
        // #1590 — the serde default now consults the process-wide
        // operator-configured default namespace; hold the test gate so
        // a concurrently-running #1590 seeding test can't bleed into
        // this unconfigured-deployment assertion.
        let _gate = crate::config::lock_configured_default_namespace_for_test();
        crate::config::set_configured_default_namespace(None);
        let cm: CreateMemory = serde_json::from_value(cm_minimal()).unwrap();
        assert_eq!(cm.namespace, "global");
    }

    /// #1590 regression — with an operator-configured
    /// `[storage].default_namespace` seeded at boot, an HTTP
    /// `CreateMemory` body that omits `namespace` lands in the
    /// configured namespace instead of the compiled `"global"`.
    /// An explicit body `namespace` still wins.
    #[test]
    fn create_memory_namespace_default_honours_configured_1590() {
        let _gate = crate::config::lock_configured_default_namespace_for_test();
        crate::config::set_configured_default_namespace(Some("alphaone".to_string()));
        let cm: CreateMemory = serde_json::from_value(cm_minimal()).unwrap();
        assert_eq!(cm.namespace, "alphaone", "#1590: configured default wins");
        let mut v = cm_minimal();
        v["namespace"] = serde_json::json!("explicit-ns");
        let cm: CreateMemory = serde_json::from_value(v).unwrap();
        assert_eq!(cm.namespace, "explicit-ns", "explicit body value wins");
        crate::config::set_configured_default_namespace(None);
    }

    #[test]
    fn create_memory_defaults_priority_to_5() {
        // Lines 181-183.
        let cm: CreateMemory = serde_json::from_value(cm_minimal()).unwrap();
        assert_eq!(cm.priority, 5);
    }

    #[test]
    fn create_memory_defaults_confidence_to_one() {
        // #1591 — the field is now `Option<f64>` so omission is
        // observable; the RESOLVED value still defaults to the
        // compiled DEFAULT_CONFIDENCE (1.0) with truthful
        // `confidence_source = "default"` provenance.
        let cm: CreateMemory = serde_json::from_value(cm_minimal()).unwrap();
        assert_eq!(cm.confidence, None, "omitted confidence must be None");
        assert!((cm.resolved_confidence() - DEFAULT_CONFIDENCE).abs() < f64::EPSILON);
        assert_eq!(
            cm.resolved_confidence_source(),
            ConfidenceSource::Default,
            "#1591: omitted confidence must stamp source=default"
        );
    }

    /// #1591 regression — an EXPLICIT caller `confidence` keeps the
    /// historical `caller_provided` provenance.
    #[test]
    fn create_memory_explicit_confidence_is_caller_provided_1591() {
        let mut v = cm_minimal();
        v["confidence"] = serde_json::json!(0.8);
        let cm: CreateMemory = serde_json::from_value(v).unwrap();
        assert_eq!(cm.confidence, Some(0.8));
        assert!((cm.resolved_confidence() - 0.8).abs() < f64::EPSILON);
        assert_eq!(
            cm.resolved_confidence_source(),
            ConfidenceSource::CallerProvided
        );
    }

    #[test]
    fn create_memory_defaults_source_to_api() {
        // Lines 187-189.
        let cm: CreateMemory = serde_json::from_value(cm_minimal()).unwrap();
        assert_eq!(cm.source, "api");
    }

    #[test]
    fn create_memory_defaults_metadata_to_empty_object() {
        let cm: CreateMemory = serde_json::from_value(cm_minimal()).unwrap();
        assert_eq!(cm.metadata, serde_json::json!({}));
    }

    #[test]
    fn recall_body_resolved_query_prefers_context() {
        let body: RecallBody = serde_json::from_value(serde_json::json!({
            "context": "c-value",
            "query": "q-value",
            "q": "qq-value",
        }))
        .unwrap();
        assert_eq!(body.resolved_query(), "c-value");
    }

    #[test]
    fn recall_body_resolved_query_falls_back_to_query_then_q() {
        let body: RecallBody =
            serde_json::from_value(serde_json::json!({"query": "q-value", "q": "qq"})).unwrap();
        assert_eq!(body.resolved_query(), "q-value");
        let body: RecallBody = serde_json::from_value(serde_json::json!({"q": "qq"})).unwrap();
        assert_eq!(body.resolved_query(), "qq");
    }

    #[test]
    fn recall_body_resolved_query_empty_when_all_absent() {
        let body: RecallBody = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(body.resolved_query(), "");
    }

    #[test]
    fn recall_body_resolved_query_trims_whitespace() {
        let body: RecallBody =
            serde_json::from_value(serde_json::json!({"context": "  spaced  "})).unwrap();
        assert_eq!(body.resolved_query(), "spaced");
    }

    #[test]
    fn search_query_defaults_limit_to_20() {
        // default_limit() returns Some(20)
        let q: SearchQuery = serde_json::from_value(serde_json::json!({"q": "x"})).unwrap();
        assert_eq!(q.limit, Some(20));
    }

    #[test]
    fn recall_query_defaults_limit_to_10() {
        // default_recall_limit() returns Some(10)
        let q: RecallQuery = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(q.limit, Some(10));
    }

    #[test]
    fn list_query_defaults_limit_to_20() {
        let q: ListQuery = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(q.limit, Some(20));
    }

    // -----------------------------------------------------------------
    // v0.7-polish coverage recovery (issue #767) — Forms 4/5/6 surface.
    // Covers the new MemoryKind variants, ConfidenceSource enum, the
    // Form 4 Citation / SourceSpan structs, and the v0.7.0 Memory
    // serde round-trip with every new field populated.
    // -----------------------------------------------------------------

    #[test]
    fn memory_kind_round_trips_every_variant_string() {
        for (s, v) in [
            ("observation", MemoryKind::Observation),
            ("reflection", MemoryKind::Reflection),
            ("persona", MemoryKind::Persona),
            ("concept", MemoryKind::Concept),
            ("entity", MemoryKind::Entity),
            ("claim", MemoryKind::Claim),
            ("relation", MemoryKind::Relation),
            ("event", MemoryKind::Event),
            ("conversation", MemoryKind::Conversation),
            ("decision", MemoryKind::Decision),
            ("goal", MemoryKind::Goal),
            ("plan", MemoryKind::Plan),
            ("step", MemoryKind::Step),
        ] {
            assert_eq!(MemoryKind::from_str(s), Some(v));
            assert_eq!(v.as_str(), s);
            assert_eq!(format!("{v}"), s);
        }
    }

    #[test]
    fn memory_kind_pillar2_goal_plan_step_round_trip() {
        // v0.8.0 Pillar 2 (#1709) — the typed-cognition cluster
        // round-trips as_str ↔ from_str and is covered by all().
        for (s, v) in [
            ("goal", MemoryKind::Goal),
            ("plan", MemoryKind::Plan),
            ("step", MemoryKind::Step),
        ] {
            assert_eq!(MemoryKind::from_str(s), Some(v));
            assert_eq!(v.as_str(), s);
            assert!(MemoryKind::all().contains(&v));
        }
    }

    #[test]
    fn memory_kind_from_str_returns_none_for_unknown() {
        assert_eq!(MemoryKind::from_str("unknown"), None);
        assert_eq!(MemoryKind::from_str(""), None);
        assert_eq!(MemoryKind::from_str("OBSERVATION"), None); // case-sensitive
    }

    #[test]
    fn memory_kind_all_enumerates_in_declaration_order() {
        let all = MemoryKind::all();
        assert_eq!(all.len(), 16);
        assert_eq!(all[0], MemoryKind::Observation);
        assert_eq!(all[1], MemoryKind::Reflection);
        assert_eq!(all[2], MemoryKind::Persona);
        assert_eq!(all[9], MemoryKind::Decision);
        // v0.8.0 Pillar 2 (#1709) — the typed-cognition cluster lands
        // after the Form-6 vocabulary, in declaration order.
        assert_eq!(all[10], MemoryKind::Goal);
        assert_eq!(all[11], MemoryKind::Plan);
        assert_eq!(all[12], MemoryKind::Step);
        // v1.0.0 epistemic typing (#1945, spec §4) — the told /
        // instruction / intervention cluster appends after Pillar-2,
        // in declaration order (never reordered — the slugs are
        // T4-frozen signed genesis bytes).
        assert_eq!(all[13], MemoryKind::Told);
        assert_eq!(all[14], MemoryKind::Instruction);
        assert_eq!(all[15], MemoryKind::Intervention);
    }

    #[test]
    fn memory_kind_epistemic_vocab_round_trips() {
        // v1.0.0 (#1945) — the three epistemic kinds round-trip through
        // the signed-byte wire slug exactly.
        for (k, slug) in [
            (MemoryKind::Told, "told"),
            (MemoryKind::Instruction, "instruction"),
            (MemoryKind::Intervention, "intervention"),
        ] {
            assert_eq!(k.as_str(), slug);
            assert_eq!(MemoryKind::from_str(slug), Some(k));
        }
    }

    #[test]
    fn kind_provenance_round_trips_and_defaults_declared() {
        assert_eq!(KindProvenance::default(), KindProvenance::Declared);
        assert_eq!(KindProvenance::all().len(), 4);
        for p in KindProvenance::all() {
            assert_eq!(KindProvenance::from_str(p.as_str()), Some(*p));
        }
        assert_eq!(
            KindProvenance::from_str("channel_derived"),
            Some(KindProvenance::ChannelDerived)
        );
        assert_eq!(KindProvenance::from_str("unknown"), None);
    }

    #[test]
    fn memory_kind_default_is_observation() {
        let k: MemoryKind = MemoryKind::default();
        assert_eq!(k, MemoryKind::Observation);
    }

    #[test]
    fn memory_kind_parse_csv_empty_string_returns_none() {
        // Whitespace-only / empty → "no filter declared" → None.
        assert_eq!(MemoryKind::parse_csv(""), None);
        assert_eq!(MemoryKind::parse_csv("   "), None);
        assert_eq!(MemoryKind::parse_csv(",,, "), None);
    }

    #[test]
    fn memory_kind_parse_csv_all_unknown_returns_empty_vec() {
        // Non-empty input with only-unknown tokens → "intentional zero
        // filter" → Some(vec![]). Distinct from None per COR-4.
        let parsed = MemoryKind::parse_csv("reflektion,observetion");
        assert_eq!(parsed, Some(Vec::new()));
    }

    #[test]
    fn memory_kind_parse_csv_mixed_known_and_unknown_drops_unknown() {
        let parsed = MemoryKind::parse_csv("reflection,bogus,concept");
        assert_eq!(
            parsed,
            Some(vec![MemoryKind::Reflection, MemoryKind::Concept])
        );
    }

    #[test]
    fn memory_kind_parse_csv_dedups_repeated_tokens() {
        let parsed = MemoryKind::parse_csv("claim,claim,event,claim");
        assert_eq!(parsed, Some(vec![MemoryKind::Claim, MemoryKind::Event]));
    }

    #[test]
    fn memory_kind_parse_csv_trims_whitespace() {
        let parsed = MemoryKind::parse_csv("  concept ,  entity ");
        assert_eq!(parsed, Some(vec![MemoryKind::Concept, MemoryKind::Entity]));
    }

    #[test]
    fn memory_kind_serialises_to_snake_case() {
        let v = serde_json::to_value(MemoryKind::Conversation).unwrap();
        assert_eq!(v, serde_json::Value::String("conversation".to_string()));
    }

    // --- v0.8.0 Pillar 2 (#1709) LifecycleState (schema v64) ---

    #[test]
    fn lifecycle_state_round_trips_every_variant_string() {
        for s in [
            LifecycleState::Open,
            LifecycleState::Active,
            LifecycleState::Blocked,
            LifecycleState::Done,
            LifecycleState::Abandoned,
            LifecycleState::Tombstoned,
            LifecycleState::Quarantined,
        ] {
            assert_eq!(LifecycleState::from_str(s.as_str()), Some(s));
        }
    }

    #[test]
    fn lifecycle_state_from_str_returns_none_for_unknown() {
        assert_eq!(LifecycleState::from_str("bogus"), None);
        assert_eq!(LifecycleState::from_str(""), None);
        assert_eq!(LifecycleState::from_str("OPEN"), None);
    }

    #[test]
    fn lifecycle_state_default_is_open() {
        assert_eq!(LifecycleState::default(), LifecycleState::Open);
    }

    #[test]
    fn lifecycle_state_all_enumerates_in_declaration_order() {
        assert_eq!(
            LifecycleState::all(),
            &[
                LifecycleState::Open,
                LifecycleState::Active,
                LifecycleState::Blocked,
                LifecycleState::Done,
                LifecycleState::Abandoned,
                LifecycleState::Tombstoned,
                LifecycleState::Quarantined,
            ]
        );
    }

    #[test]
    fn lifecycle_state_is_terminal_only_done_and_abandoned() {
        assert!(LifecycleState::Done.is_terminal());
        assert!(LifecycleState::Abandoned.is_terminal());
        // v0.9.0 G13-mem (#1859) — the consolidation logical-delete state
        // is terminal too.
        assert!(LifecycleState::Tombstoned.is_terminal());
        // v1.0.0 R19/A3 (#1948) — the system-only quarantine state is terminal.
        assert!(LifecycleState::Quarantined.is_terminal());
        assert!(!LifecycleState::Open.is_terminal());
        assert!(!LifecycleState::Active.is_terminal());
        assert!(!LifecycleState::Blocked.is_terminal());
    }

    #[test]
    fn lifecycle_quarantined_is_system_only_and_unreachable_by_transition() {
        // Quarantined is absent from `can_transition_to` for every source
        // (no caller path reaches it), and flagged system-only.
        for from in LifecycleState::all() {
            assert!(
                !from.can_transition_to(LifecycleState::Quarantined),
                "{from} -> Quarantined must be an illegal caller transition"
            );
        }
        assert!(LifecycleState::Quarantined.is_system_only());
        assert!(LifecycleState::Tombstoned.is_system_only());
        assert!(!LifecycleState::Open.is_system_only());
        assert!(!LifecycleState::Done.is_system_only());
    }

    #[test]
    fn lifecycle_recall_visible_allowlist_is_fail_closed() {
        // Exactly the RECALL_VISIBLE_LIFECYCLE_STATES set is visible; the
        // system-only states are hidden (fail-closed).
        assert!(LifecycleState::Open.is_recall_visible());
        assert!(LifecycleState::Active.is_recall_visible());
        assert!(LifecycleState::Blocked.is_recall_visible());
        assert!(LifecycleState::Done.is_recall_visible());
        assert!(LifecycleState::Abandoned.is_recall_visible());
        assert!(!LifecycleState::Tombstoned.is_recall_visible());
        assert!(!LifecycleState::Quarantined.is_recall_visible());
        // Every allow-list member is non-system-only, and vice-versa.
        for st in LifecycleState::all() {
            assert_eq!(st.is_recall_visible(), !st.is_system_only());
        }
    }

    #[test]
    fn lifecycle_dequarantine_target_only_for_quarantined() {
        assert_eq!(
            LifecycleState::Quarantined.dequarantine_target(),
            Some(LifecycleState::Open)
        );
        for st in LifecycleState::all() {
            if *st != LifecycleState::Quarantined {
                assert_eq!(st.dequarantine_target(), None);
            }
        }
    }

    #[test]
    fn lifecycle_visible_clause_builds_fail_closed_allowlist() {
        // The SQL twin: an allow-list IN(...) over the visible vocabulary,
        // with the NULL-legacy escape, derived from the const (not literals).
        let bare = lifecycle_visible_clause("");
        assert!(bare.contains("lifecycle_state IS NULL"));
        assert!(bare.contains("lifecycle_state IN ("));
        for st in RECALL_VISIBLE_LIFECYCLE_STATES {
            assert!(bare.contains(&format!("'{}'", st.as_str())), "missing {st}");
        }
        // System-only states are NOT in the clause (fail-closed).
        assert!(!bare.contains("'tombstoned'"));
        assert!(!bare.contains("'quarantined'"));
        // Alias-qualified form.
        let aliased = lifecycle_visible_clause("m");
        assert!(aliased.contains("m.lifecycle_state IN ("));
    }

    #[test]
    fn lifecycle_state_transition_matrix_is_enforced() {
        use LifecycleState::{Abandoned, Active, Blocked, Done, Open};
        // Legal edges.
        assert!(Open.can_transition_to(Active));
        assert!(Open.can_transition_to(Abandoned));
        assert!(Active.can_transition_to(Blocked));
        assert!(Active.can_transition_to(Done));
        assert!(Active.can_transition_to(Abandoned));
        assert!(Blocked.can_transition_to(Active));
        assert!(Blocked.can_transition_to(Abandoned));
        // Illegal: skipping active.
        assert!(!Open.can_transition_to(Done));
        assert!(!Open.can_transition_to(Blocked));
        // Illegal: no self-loops.
        assert!(!Open.can_transition_to(Open));
        assert!(!Active.can_transition_to(Active));
        assert!(!Blocked.can_transition_to(Blocked));
        // Illegal: terminals go nowhere.
        for to in LifecycleState::all() {
            assert!(!Done.can_transition_to(*to), "done -> {to} must be illegal");
            assert!(
                !Abandoned.can_transition_to(*to),
                "abandoned -> {to} must be illegal"
            );
        }
        // Illegal: blocked cannot jump straight to done (must re-activate).
        assert!(!Blocked.can_transition_to(Done));
    }

    #[test]
    fn lifecycle_state_serialises_to_snake_case() {
        let v = serde_json::to_value(LifecycleState::Abandoned).unwrap();
        assert_eq!(v, serde_json::Value::String("abandoned".to_string()));
    }

    #[test]
    fn memory_default_lifecycle_state_is_open() {
        let m = Memory::default();
        assert_eq!(m.lifecycle_state, LifecycleState::Open);
    }

    #[test]
    fn confidence_source_round_trips_every_variant_string() {
        for (s, v) in [
            ("caller_provided", ConfidenceSource::CallerProvided),
            ("auto_derived", ConfidenceSource::AutoDerived),
            ("calibrated", ConfidenceSource::Calibrated),
            ("decayed", ConfidenceSource::Decayed),
            // v0.7.0 issue #1242 — curator-engine output bucket
            // (atom rows + persona rows). Distinct from
            // `auto_derived` (which is the Form 5 engine's
            // signal-based derivation).
            ("curator_derived", ConfidenceSource::CuratorDerived),
            // v0.7.x issue #1591 — caller omitted `confidence`; the
            // compiled DEFAULT_CONFIDENCE fallback was stamped.
            ("default", ConfidenceSource::Default),
        ] {
            assert_eq!(ConfidenceSource::from_str(s), Some(v));
            assert_eq!(v.as_str(), s);
            assert_eq!(format!("{v}"), s);
        }
    }

    /// #1600 regression — `EditSource` wire vocabulary round-trips
    /// every variant (incl. the new `agent`), `ALL` covers the closed
    /// set, and `agent` keeps Human's in-place mutation semantics
    /// (does NOT route append-and-archive).
    #[test]
    fn edit_source_agent_variant_wire_and_semantics_1600() {
        for v in EditSource::ALL {
            assert_eq!(
                EditSource::from_str(v.as_str()),
                Some(v),
                "EditSource wire string must round-trip"
            );
        }
        assert_eq!(EditSource::from_str("agent"), Some(EditSource::Agent));
        assert_eq!(EditSource::Agent.as_str(), "agent");
        assert!(
            !EditSource::Agent.appends_and_archives(),
            "#1600: Agent mutates in place exactly like Human"
        );
        assert!(EditSource::Llm.appends_and_archives());
        assert!(EditSource::Hook.appends_and_archives());
        // serde wire compat: snake_case rename matches as_str.
        assert_eq!(
            serde_json::to_value(EditSource::Agent).unwrap(),
            serde_json::Value::String("agent".to_string())
        );
        assert_eq!(EditSource::from_str("robot"), None, "unknown stays None");
    }

    /// #1600 regression — omitted `edit_source` derives from the
    /// resolved caller id: `ai:`-prefixed NHI ids default to `Agent`,
    /// every other shape keeps the historical `Human` default.
    #[test]
    fn edit_source_default_for_agent_id_matrix_1600() {
        assert_eq!(
            EditSource::default_for_agent_id("ai:claude-code@host:pid-1"),
            EditSource::Agent
        );
        assert_eq!(
            EditSource::default_for_agent_id("host:box:pid-2-abcd1234"),
            EditSource::Human
        );
        assert_eq!(
            EditSource::default_for_agent_id("anonymous:pid-3-ffff0000"),
            EditSource::Human
        );
        assert_eq!(EditSource::default_for_agent_id("alice"), EditSource::Human);
    }

    #[test]
    fn confidence_source_from_str_returns_none_for_unknown() {
        assert_eq!(ConfidenceSource::from_str("unknown"), None);
        assert_eq!(ConfidenceSource::from_str(""), None);
    }

    #[test]
    fn confidence_source_default_is_caller_provided() {
        let v: ConfidenceSource = ConfidenceSource::default();
        assert_eq!(v, ConfidenceSource::CallerProvided);
    }

    #[test]
    fn confidence_source_serialises_to_snake_case() {
        let v = serde_json::to_value(ConfidenceSource::AutoDerived).unwrap();
        assert_eq!(v, serde_json::Value::String("auto_derived".to_string()));
    }

    #[test]
    fn confidence_signals_default_has_expected_values() {
        let s = ConfidenceSignals::default();
        assert!((s.source_age_days - 0.0).abs() < f64::EPSILON);
        assert!(!s.atom_derivation);
        assert_eq!(s.prior_corroboration_count, 0);
        assert!((s.freshness_factor - 1.0).abs() < f64::EPSILON);
        assert!((s.baseline_per_source - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn confidence_signals_round_trips_through_serde() {
        let s = ConfidenceSignals {
            source_age_days: 12.5,
            atom_derivation: true,
            prior_corroboration_count: 3,
            freshness_factor: 0.75,
            baseline_per_source: 0.62,
        };
        let v = serde_json::to_value(&s).unwrap();
        let back: ConfidenceSignals = serde_json::from_value(v).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn source_span_round_trips_through_serde() {
        let span = SourceSpan { start: 12, end: 34 };
        let v = serde_json::to_value(span).unwrap();
        let back: SourceSpan = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(back, span);
        // JSON shape: {"start": 12, "end": 34}.
        assert_eq!(v["start"], 12);
        assert_eq!(v["end"], 34);
    }

    #[test]
    fn citation_round_trips_through_serde_with_optional_fields_unset() {
        let c = Citation {
            uri: "doc:abc123".to_string(),
            accessed_at: "2026-01-01T00:00:00Z".to_string(),
            hash: None,
            span: None,
        };
        let s = serde_json::to_string(&c).unwrap();
        // skip_serializing_if drops the None fields entirely.
        assert!(!s.contains("hash"));
        assert!(!s.contains("span"));
        let back: Citation = serde_json::from_str(&s).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn citation_round_trips_with_hash_and_span_set() {
        let c = Citation {
            uri: "uri:https://example.com/paper".to_string(),
            accessed_at: "2026-02-03T04:05:06Z".to_string(),
            hash: Some("a".repeat(64)),
            span: Some(SourceSpan { start: 0, end: 100 }),
        };
        let v = serde_json::to_value(&c).unwrap();
        let back: Citation = serde_json::from_value(v).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn memory_default_populates_form4_and_form5_defaults() {
        let m = Memory::default();
        assert!(m.citations.is_empty());
        assert!(m.source_uri.is_none());
        assert!(m.source_span.is_none());
        assert_eq!(m.confidence_source, ConfidenceSource::CallerProvided);
        assert!(m.confidence_signals.is_none());
        assert!(m.confidence_decayed_at.is_none());
        assert_eq!(m.memory_kind, MemoryKind::Observation);
        assert!(m.entity_id.is_none());
        assert!(m.persona_version.is_none());
    }

    #[test]
    fn memory_round_trips_with_all_v070_form_fields_populated() {
        let mut m = Memory::default();
        m.id = "mem-form".to_string();
        m.title = "fact-bearer".to_string();
        m.content = "the build broke at 14:32".to_string();
        m.created_at = "2026-05-01T00:00:00Z".to_string();
        m.updated_at = "2026-05-01T00:00:00Z".to_string();
        m.memory_kind = MemoryKind::Claim;
        m.entity_id = Some("entity-xyz".to_string());
        m.persona_version = Some(7);
        m.citations = vec![Citation {
            uri: "doc:src-1".to_string(),
            accessed_at: "2026-05-01T00:00:00Z".to_string(),
            hash: None,
            span: None,
        }];
        m.source_uri = Some("uri:https://example.com".to_string());
        m.source_span = Some(SourceSpan { start: 5, end: 10 });
        m.confidence_source = ConfidenceSource::Calibrated;
        m.confidence_signals = Some(ConfidenceSignals::default());
        m.confidence_decayed_at = Some("2026-04-01T00:00:00Z".to_string());

        let s = serde_json::to_string(&m).unwrap();
        let back: Memory = serde_json::from_str(&s).unwrap();
        assert_eq!(back.id, m.id);
        assert_eq!(back.memory_kind, MemoryKind::Claim);
        assert_eq!(back.entity_id.as_deref(), Some("entity-xyz"));
        assert_eq!(back.persona_version, Some(7));
        assert_eq!(back.citations.len(), 1);
        assert_eq!(back.citations[0].uri, "doc:src-1");
        assert_eq!(back.source_uri.as_deref(), Some("uri:https://example.com"));
        assert_eq!(back.source_span, Some(SourceSpan { start: 5, end: 10 }));
        assert_eq!(back.confidence_source, ConfidenceSource::Calibrated);
        assert!(back.confidence_signals.is_some());
        assert_eq!(
            back.confidence_decayed_at.as_deref(),
            Some("2026-04-01T00:00:00Z")
        );
    }

    #[test]
    fn memory_deserialises_pre_form4_payload_without_form4_fields() {
        // A pre-Form-4 payload omits citations / source_uri / source_span /
        // confidence_source / confidence_signals / confidence_decayed_at.
        // serde defaults must populate them.
        let json = serde_json::json!({
            "id": "old-mem",
            "tier": Tier::Long.as_str(),
            "namespace": "ns",
            "title": "t",
            "content": "c",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "api",
            "access_count": 0,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
            "metadata": {},
        });
        let m: Memory = serde_json::from_value(json).unwrap();
        assert!(m.citations.is_empty());
        assert!(m.source_uri.is_none());
        assert!(m.source_span.is_none());
        assert_eq!(m.confidence_source, ConfidenceSource::CallerProvided);
        assert!(m.confidence_signals.is_none());
        assert!(m.confidence_decayed_at.is_none());
        assert!(m.entity_id.is_none());
        assert!(m.persona_version.is_none());
        assert_eq!(m.memory_kind, MemoryKind::Observation);
    }

    #[test]
    fn recall_body_resolved_kinds_handles_all_keyword() {
        let body: RecallBody = serde_json::from_value(serde_json::json!({
            "kinds": "ALL",
        }))
        .unwrap();
        assert_eq!(body.resolved_kinds(), None);
    }

    #[test]
    fn recall_body_resolved_kinds_csv_parses_known_tokens() {
        let body: RecallBody = serde_json::from_value(serde_json::json!({
            "kinds": "concept,claim",
        }))
        .unwrap();
        let kinds = body.resolved_kinds().unwrap();
        assert!(kinds.contains(&MemoryKind::Concept));
        assert!(kinds.contains(&MemoryKind::Claim));
    }

    #[test]
    fn recall_body_resolved_kinds_array_parses_known_tokens() {
        let body: RecallBody = serde_json::from_value(serde_json::json!({
            "kinds": ["event", "entity", "bogus", "entity"],
        }))
        .unwrap();
        let kinds = body.resolved_kinds().unwrap();
        // Deduped + unknown dropped.
        assert_eq!(kinds, vec![MemoryKind::Event, MemoryKind::Entity]);
    }

    #[test]
    fn recall_body_resolved_kinds_empty_array_returns_none() {
        let body: RecallBody = serde_json::from_value(serde_json::json!({
            "kinds": [],
        }))
        .unwrap();
        assert_eq!(body.resolved_kinds(), None);
    }

    #[test]
    fn recall_body_resolved_kinds_only_unknown_array_returns_empty_vec() {
        // COR-4 distinction: explicit array with only unknowns returns
        // Some(vec![]) (intentional zero-match) — not None.
        let body: RecallBody = serde_json::from_value(serde_json::json!({
            "kinds": ["reflektion"],
        }))
        .unwrap();
        assert_eq!(body.resolved_kinds(), Some(Vec::new()));
    }

    #[test]
    fn recall_body_resolved_kinds_absent_returns_none() {
        let body: RecallBody = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(body.resolved_kinds(), None);
    }

    #[test]
    fn recall_body_resolved_kinds_non_string_non_array_returns_none() {
        // A number, object, bool etc. is neither string nor array → None.
        let body: RecallBody = serde_json::from_value(serde_json::json!({
            "kinds": 42,
        }))
        .unwrap();
        assert_eq!(body.resolved_kinds(), None);
    }

    #[test]
    fn recall_query_resolved_kinds_handles_all_keyword() {
        let q: RecallQuery = serde_json::from_value(serde_json::json!({
            "kinds": "all",
        }))
        .unwrap();
        assert_eq!(q.resolved_kinds(), None);
    }

    #[test]
    fn recall_query_resolved_kinds_parses_csv() {
        let q: RecallQuery = serde_json::from_value(serde_json::json!({
            "kinds": "decision,relation",
        }))
        .unwrap();
        let kinds = q.resolved_kinds().unwrap();
        assert!(kinds.contains(&MemoryKind::Decision));
        assert!(kinds.contains(&MemoryKind::Relation));
    }

    #[test]
    fn recall_query_resolved_kinds_absent_returns_none() {
        let q: RecallQuery = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(q.resolved_kinds(), None);
    }

    #[test]
    fn create_memory_accepts_form4_fields_when_present() {
        let cm: CreateMemory = serde_json::from_value(serde_json::json!({
            "title": "t",
            "content": "c",
            "citations": [{
                "uri": "doc:abc",
                "accessed_at": "2026-01-01T00:00:00Z",
            }],
            "source_uri": "uri:https://example.com",
            "source_span": {"start": 0, "end": 5},
        }))
        .unwrap();
        assert_eq!(cm.citations.len(), 1);
        assert_eq!(cm.source_uri.as_deref(), Some("uri:https://example.com"));
        assert_eq!(cm.source_span, Some(SourceSpan { start: 0, end: 5 }));
    }

    // ─────────────────────────────────────────────────────────────────────
    // #1385 — CreateMemory now honours caller-supplied `kind`. Pre-fix
    // the field did not exist on the struct, so HTTP `POST
    // /api/v1/memories` silently dropped it and every HTTP-created row
    // landed as `Observation`. That made the Form 6 recall `kinds`
    // filter useless against the HTTP write surface (a v3 NHI
    // assessment defect; live alice repro returned 0 rows for
    // kinds=["claim","decision"] against rows the caller had stored
    // with those exact kind tokens).
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn create_memory_kind_field_deserialises_known_tokens() {
        for token in [
            "observation",
            "reflection",
            "persona",
            "concept",
            "entity",
            "claim",
            "relation",
            "event",
            "conversation",
            "decision",
        ] {
            let cm: CreateMemory = serde_json::from_value(serde_json::json!({
                "title": "t",
                "content": "c",
                "kind": token,
            }))
            .unwrap();
            assert_eq!(
                cm.kind.as_deref(),
                Some(token),
                "kind={token} must round-trip on the wire"
            );
            // And the handler parses it back into the typed enum on
            // assembly. Mirror the exact pattern the handler uses.
            let parsed = cm.kind.as_deref().and_then(MemoryKind::from_str);
            assert_eq!(
                parsed.map(|k| k.as_str()),
                Some(token),
                "kind={token} must parse back into MemoryKind",
            );
        }
    }

    #[test]
    fn create_memory_kind_field_absent_defaults_to_none() {
        let cm: CreateMemory = serde_json::from_value(serde_json::json!({
            "title": "t",
            "content": "c",
        }))
        .unwrap();
        assert_eq!(cm.kind, None);
        // Handler-side: absent → falls through to `Observation`.
        let resolved = cm
            .kind
            .as_deref()
            .and_then(MemoryKind::from_str)
            .unwrap_or_default();
        assert_eq!(resolved, MemoryKind::Observation);
    }

    #[test]
    fn create_memory_kind_field_unknown_token_silently_falls_through_to_observation() {
        // Matches MCP `memory_store` forward-compat posture
        // (`src/mcp/tools/store/validation.rs:207-213`): an unknown
        // kind token is treated as omission so a newer-client variant
        // landing on an older daemon still writes, just without the
        // typed discriminator. Distinct from the COR-4 invariant on
        // recall `kinds` filters where an explicit zero-match filter
        // must NOT collapse into "match all".
        let cm: CreateMemory = serde_json::from_value(serde_json::json!({
            "title": "t",
            "content": "c",
            "kind": "future_variant_v100",
        }))
        .unwrap();
        assert_eq!(cm.kind.as_deref(), Some("future_variant_v100"));
        let resolved = cm
            .kind
            .as_deref()
            .and_then(MemoryKind::from_str)
            .unwrap_or_default();
        assert_eq!(
            resolved,
            MemoryKind::Observation,
            "unknown kind token must silently fall through to Observation \
             for forward-compat with future-variant clients",
        );
    }
}
