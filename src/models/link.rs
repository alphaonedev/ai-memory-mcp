// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

// Canonical relation spellings duplicated across `from_str` / `as_str`
// and the reflect / contradiction response keys (#1558 batch 6).
pub(crate) const REL_CONTRADICTS: &str = "contradicts";
pub(crate) const REL_REFLECTS_ON: &str = "reflects_on";
pub(crate) const REL_DERIVES_FROM: &str = "derives_from";
// v0.8.0 Pillar-2 (Typed Cognition, #1709) — the Goal/Plan/Step wiring
// relations. Each spelling is ≥ 10 chars and is referenced from both
// `from_str` and `as_str` (plus the SQL CHECK mirror in
// `crate::validate::VALID_RELATIONS`), so it follows the named-const
// pattern of the long relations above rather than a bare literal.
pub(crate) const REL_DECOMPOSES_INTO: &str = "decomposes_into";
pub(crate) const REL_DEPENDS_ON: &str = "depends_on";
pub(crate) const REL_ADVANCES: &str = "advances";

/// v0.7 Track H — attestation level for a `memory_links` row.
///
/// H2 (#566) and H3 (#572) already write the three string variants
/// directly into the `memory_links.attest_level` TEXT column
/// (`"unsigned"`, `"self_signed"`, `"peer_attested"`). H4 formalises
/// the enum so the `memory_verify` MCP tool — and any future verifier
/// surface — can reason in terms of a closed set rather than an
/// open-ended string.
///
/// `#[serde(rename_all = "snake_case")]` keeps the wire shape byte-
/// identical to what the database column already holds. The
/// [`AttestLevel::from_str`] / [`AttestLevel::as_str`] helpers exist
/// because the column is read as a `String` in many call sites that
/// are not deserialising through serde (e.g. `rusqlite::Row::get`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestLevel {
    /// No signature on the row, or no key enrolled for `observed_by` on
    /// the receiver. Federation back-compat default — unsigned rows
    /// still land but downstream consumers know they cannot verify.
    Unsigned,
    /// Row was signed locally by this writer (H2 outbound path).
    SelfSigned,
    /// Row arrived from a peer with a signature that verified against
    /// the enrolled `observed_by` public key on this host (H3 inbound
    /// path).
    PeerAttested,
    /// v0.7.0 #1389 L4 / RFC-0001 — capture_turn host-signed memory.
    /// Distinct from `PeerAttested` (which is federation H3 inbound):
    /// `SignedByPeer` means an out-of-process HOST supplied a
    /// `host_signature_b64` + `host_pubkey_b64`; the substrate
    /// verified the signature against
    /// `AI_MEMORY_L4_HOST_PUBKEY_ALLOWLIST` and the canonical-bytes
    /// encoding. Used at `src/mcp/tools/capture_turn.rs::556`.
    /// Closes F-C9 spec-drift (#1430).
    SignedByPeer,
    /// v0.7.0 — daemon-signed governance-audit row. Used by
    /// `crate::governance::audit::sign_with_daemon_key` when a daemon
    /// keypair is installed and the substrate emits a Custom-action
    /// refusal row to the signed_events chain. Distinct from
    /// `SelfSigned` (H2 link-write outbound) — this variant is the
    /// substrate's OWN signature on its OWN audit emissions, not on
    /// content the substrate received from a caller. Closes F-C9
    /// spec-drift (#1430).
    DaemonSigned,
    /// v0.9.0 G9 (#1826) — governance-audit row signed by the DISTINCT
    /// RECORDER key (three-key Recorder/Judge/Stopper signing-layer
    /// separation). Distinct from `DaemonSigned`: the recorder key has
    /// SEPARATE custody (`AI_MEMORY_RECORDER_KEY_DIR`) and its signature
    /// commits to the domain-separated preimage
    /// `DOMAIN_RECORDER || signing_input_bytes(payload_hash, cause_hash)`
    /// (so a judge/stopper key cannot forge a recorder row and vice-versa).
    /// Verified per-row against the out-of-band-enrolled
    /// `AI_MEMORY_RECORDER_PUBKEY` in `verify_chain`. Additive/opt-in:
    /// unset recorder key → rows stay `DaemonSigned` (byte-identical legacy).
    RecorderSigned,
    /// v0.9.0 G13 (#1828) — `signed_events` WITNESS row for an
    /// identity-lineage succession record (`identity.lineage.*` event
    /// types). The row's `signature` is the succession signature by the
    /// record's PREDECESSOR key over the `LINEAGE_DOMAIN`-tagged
    /// canonical bytes — NOT a daemon/recorder signature — so the
    /// per-row chain verifier skips it and
    /// `crate::identity::lineage::verify_lineage` owns its validity
    /// (chain-linkage vs succession-validity are disjoint properties,
    /// same split `verify_chain` documents for role keys).
    LineageSigned,
}

impl AttestLevel {
    /// Parse the string form stored in `memory_links.attest_level` /
    /// `signed_events.attest_level`.
    ///
    /// Returns `None` for unknown values so callers can decide whether
    /// to treat the column as legacy/`unsigned` or surface an error.
    /// Keeps the unit-of-truth on the database column shape — H2/H3
    /// already write the canonical lowercase snake_case strings.
    /// v0.7.0 #1389 L4 + governance-audit additions parse via the
    /// `signed_by_peer` and `daemon_signed` arms.
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "unsigned" => Some(Self::Unsigned),
            "self_signed" => Some(Self::SelfSigned),
            "peer_attested" => Some(Self::PeerAttested),
            "signed_by_peer" => Some(Self::SignedByPeer),
            "daemon_signed" => Some(Self::DaemonSigned),
            "recorder_signed" => Some(Self::RecorderSigned),
            "lineage_signed" => Some(Self::LineageSigned),
            _ => None,
        }
    }

    /// Canonical wire string for this variant. Mirrors the `serde`
    /// rename_all and the literals every writer (H2/H3/L4/governance-
    /// audit) already writes to the DB.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Unsigned => "unsigned",
            Self::SelfSigned => "self_signed",
            Self::PeerAttested => "peer_attested",
            Self::SignedByPeer => "signed_by_peer",
            Self::DaemonSigned => "daemon_signed",
            Self::RecorderSigned => "recorder_signed",
            Self::LineageSigned => "lineage_signed",
        }
    }
}

impl std::fmt::Display for AttestLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// v0.7.0 fix campaign R1-M4 — typed relation closed-set for
/// `memory_links.relation`. Paired with the SQL-side CHECK constraint
/// added by the same R1-M4 migration: defense-in-depth so direct-SQL
/// writers can no longer slip an unknown relation past the Rust
/// validator.
///
/// `#[serde(rename_all = "snake_case")]` keeps the wire shape and the
/// `memory_links.relation` TEXT column byte-identical to the values
/// the v0.6.x codebase already writes (`"related_to"`, `"supersedes"`,
/// `"contradicts"`, `"derived_from"`, `"reflects_on"`, plus the
/// v0.7.0 WT-1-A addition `"derives_from"` — distinct from
/// `"derived_from"` as the atomisation-provenance variant). The
/// [`MemoryLinkRelation::from_str`] / [`MemoryLinkRelation::as_str`]
/// helpers exist because the column is read as a `String` in many
/// call sites that are not deserialising through serde (e.g.
/// `rusqlite::Row::get`).
///
/// # ⚠️ FOOTGUN: `DerivedFrom` (`derived_from`) vs `DerivesFrom`
/// (`derives_from`) — NOT duplicates, OPPOSITE directions ([#2055])
///
/// These two variants differ by a single character (`derived` vs
/// `derives`) and are trivially confused by anyone authoring links,
/// reading a KG traversal, or reasoning about the [`Self::LINEAGE`]
/// trio — but they carry **opposite cardinalities and opposite
/// authorship**:
///
/// | Variant | Wire slug | Cardinality | Produced by | Direction |
/// |---|---|---|---|---|
/// | [`Self::DerivedFrom`] | `derived_from` | **N → 1** (many sources, one result) | consolidation-merge | `source_id` = the merged memory, `target_id` = a source it absorbed |
/// | [`Self::DerivesFrom`] | `derives_from` | **1 → N** (one source, many results) | atomisation-split | `source_id` = an atom, `target_id` = the parent it was split from |
///
/// Worked example — consolidating memories A + B into C, then
/// atomising C into atoms X + Y, emits exactly these four edges:
///
/// ```text
/// C --derived_from--> A     (consolidation: C ABSORBED A)
/// C --derived_from--> B     (consolidation: C ABSORBED B)
/// X --derives_from--> C     (atomisation: X was SPLIT OUT of C)
/// Y --derives_from--> C     (atomisation: Y was SPLIT OUT of C)
/// ```
///
/// Neither variant is a duplicate of the other and **NEITHER MAY BE
/// RENAMED**: both wire slugs are persisted in `memory_links.relation`,
/// enumerated in the SQL-side CHECK constraint
/// (`crate::validate::VALID_RELATIONS`), and serialized over the wire —
/// a rename is a breaking migration + wire change (tracked separately;
/// coordinate with any future v1.x follow-up before touching either
/// spelling). When authoring a link, read the table above rather than
/// pattern-matching on the variant name's prefix.
///
/// [#2055]: https://github.com/alphaonedev/ai-memory-mcp/issues/2055
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryLinkRelation {
    /// Generic association. Default for `LinkBody::resolved` and the
    /// `INSERT` default in the SQL schema.
    RelatedTo,
    /// Source supersedes target (newer / authoritative version).
    Supersedes,
    /// Source contradicts target (incompatible claims).
    Contradicts,
    /// Source is derived from target (consolidation provenance).
    DerivedFrom,
    /// Source is a reflection on target (recursive-learning provenance,
    /// v0.7.0 Task 1/8).
    ReflectsOn,
    /// Source is an atomisation derivative of target — the typed,
    /// signable, federation-safe expression of the structural
    /// `memories.atom_of` FK introduced in v0.7.0 WT-1-A (schema v36
    /// sqlite / v35 postgres). Atom row -> parent memory. Participates
    /// in `find_paths` traversal alongside the other relations.
    /// Distinct from `DerivedFrom` (consolidation provenance):
    /// atomisation is a finer-grained, recoverable split that emits
    /// one `derives_from` edge per atom; consolidation merges several
    /// memories into one and emits `derived_from` edges from the
    /// consolidated memory back to each source.
    DerivesFrom,
    /// v0.8.0 Pillar-2 (Typed Cognition, #1709) — a parent breaks down
    /// into children: a `Goal` decomposes_into `Plan`s; a `Plan`
    /// decomposes_into `Step`s (the [`crate::models::MemoryKind`]
    /// Goal/Plan/Step vocabulary). Directionality is **parent → child**
    /// (`source_id` = the parent, `target_id` = the child) — the
    /// structural inverse of the provenance relations `DerivedFrom` /
    /// `ReflectsOn` / `DerivesFrom`, which all point newer/derived →
    /// older/source. This is the structural decomposition spine of a
    /// typed-cognition plan tree.
    DecomposesInto,
    /// v0.8.0 Pillar-2 (Typed Cognition, #1709) — an ordering /
    /// prerequisite edge between SIBLINGS: a `Step` depends_on another
    /// `Step` that must complete first. Directionality is **dependent →
    /// prerequisite** (`source_id` = the step that waits, `target_id` =
    /// the step it waits on). This is the memory-link-vocab analogue of
    /// the action-DAG `EdgeType::Requires` ordering concept, but it is
    /// the typed `memory_links` RELATION — deliberately distinct from
    /// and NOT a duplicate of `crate::models::action::EdgeType`, which
    /// models the executable action graph rather than the memory graph.
    DependsOn,
    /// v0.8.0 Pillar-2 (Typed Cognition, #1709) — a child contributes
    /// progress toward an ANCESTOR: a `Step` advances a `Plan` or
    /// `Goal`. Directionality is **child → ancestor** (`source_id` =
    /// the contributing child, `target_id` = the ancestor it advances).
    /// It is the progress-rollup counterpart of `DecomposesInto`: where
    /// `DecomposesInto` runs parent → child to describe structure,
    /// `advances` runs child → ancestor to describe contribution, so a
    /// traversal can roll Step completion up into Plan / Goal progress
    /// without re-walking the decomposition spine in reverse.
    Advances,
}

impl MemoryLinkRelation {
    /// Parse the string form stored in `memory_links.relation`.
    ///
    /// Returns `None` for unknown values so callers can decide whether
    /// to reject with a typed error or fall back to a default. The
    /// canonical strings are the SQL-side CHECK constraint membership
    /// list — keep this list in sync with the migration.
    ///
    /// ⚠️ Authoring a link by hand (e.g. `MemoryLinkRelation::from_str("derived_from")`)?
    /// Double-check you want `"derived_from"` and not `"derives_from"` —
    /// see the FOOTGUN section of [`MemoryLinkRelation`]'s type-level doc
    /// comment before picking one; the names differ by a single character
    /// but point in OPPOSITE directions (`derived_from` = N→1
    /// consolidation-merge, `derives_from` = 1→N atomisation-split).
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "related_to" => Some(Self::RelatedTo),
            "supersedes" => Some(Self::Supersedes),
            REL_CONTRADICTS => Some(Self::Contradicts),
            "derived_from" => Some(Self::DerivedFrom),
            REL_REFLECTS_ON => Some(Self::ReflectsOn),
            REL_DERIVES_FROM => Some(Self::DerivesFrom),
            REL_DECOMPOSES_INTO => Some(Self::DecomposesInto),
            REL_DEPENDS_ON => Some(Self::DependsOn),
            REL_ADVANCES => Some(Self::Advances),
            _ => None,
        }
    }

    /// Canonical wire string for this variant. Mirrors the `serde`
    /// rename_all and the literals every existing call site already
    /// writes to the DB.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RelatedTo => "related_to",
            Self::Supersedes => "supersedes",
            Self::Contradicts => REL_CONTRADICTS,
            Self::DerivedFrom => "derived_from",
            Self::ReflectsOn => REL_REFLECTS_ON,
            Self::DerivesFrom => REL_DERIVES_FROM,
            Self::DecomposesInto => REL_DECOMPOSES_INTO,
            Self::DependsOn => REL_DEPENDS_ON,
            Self::Advances => REL_ADVANCES,
        }
    }

    /// Canonical default — matches the `DEFAULT 'related_to'` clause
    /// on `memory_links.relation` in the schema and the fallback in
    /// `LinkBody::resolved`.
    #[must_use]
    pub const fn default_relation() -> Self {
        Self::RelatedTo
    }

    /// Total number of `MemoryLinkRelation` variants. SSOT for the
    /// "ai-memory supports N typed link relations at v0.7.0" narrative
    /// in CLAUDE.md / README.md / ROADMAP.md / release-notes — adding
    /// a new variant requires bumping this const AND the [`all()`]
    /// slice in the same commit, or the parity test pin in
    /// `tests/memory_link_relation_count_invariant.rs` fails the build.
    pub const COUNT: usize = 9;

    /// Canonical enumeration of every variant in declaration order
    /// (`related_to`, `supersedes`, `contradicts`, `derived_from`,
    /// `reflects_on`, `derives_from`, `decomposes_into`, `depends_on`,
    /// `advances`). Use this anywhere external code would otherwise
    /// hand-roll the list — kg traversal, federation peer-handshake,
    /// capability advertisement, parity tests. The `length == COUNT`
    /// invariant is pinned by
    /// `tests/memory_link_relation_count_invariant.rs`.
    #[must_use]
    pub const fn all() -> &'static [Self; Self::COUNT] {
        &[
            Self::RelatedTo,
            Self::Supersedes,
            Self::Contradicts,
            Self::DerivedFrom,
            Self::ReflectsOn,
            Self::DerivesFrom,
            Self::DecomposesInto,
            Self::DependsOn,
            Self::Advances,
        ]
    }

    /// v0.9.0 G13-mem (#1859) — the provenance subset of relations that
    /// constitute the memory-derivation lineage-DAG. Every edge in this set
    /// points child(`source_id`) -> parent(`target_id`) (newer/derived ->
    /// older/source), so a recursive traversal restricted to exactly this
    /// set walks a strict provenance DAG. All three are already members of
    /// the closed `memory_links.relation` CHECK allowlist, so the
    /// lineage-DAG is a VIEW over existing edges — it adds NO new relation.
    /// Keep this array in lockstep with [`Self::is_lineage`]; the pairing
    /// is pinned by `tests/memory_link_relation_count_invariant.rs`.
    // M-STRONG-TYPES: the lineage set is a typed const, not a stringly
    // literal list re-spelled at each traversal / query call site.
    pub const LINEAGE: [Self; 3] = [Self::DerivedFrom, Self::ReflectsOn, Self::DerivesFrom];

    /// Whether this relation participates in the lineage-DAG provenance set
    /// [`Self::LINEAGE`] (`derived_from` / `reflects_on` / `derives_from`).
    #[must_use]
    pub const fn is_lineage(self) -> bool {
        matches!(
            self,
            Self::DerivedFrom | Self::ReflectsOn | Self::DerivesFrom
        )
    }
}

/// v0.9.0 G13-mem (#1859) — one node on a memory-derivation lineage-DAG
/// walk (an ancestor or a descendant of the query root), carrying the
/// edge relation that reached it and its hop-distance from the root.
///
/// `cid` is the node's stable content-address, resolved from the edge's
/// stored `source_cid`/`target_cid` mirror when present, else a LEFT JOIN
/// fallback to the live `memories.cid`. `None` when neither carries one
/// (legacy edge into a pre-v74 row). Per COND 2 (#1859) the cid is an
/// advisory anchor — `memories.cid` has only a NON-unique index and
/// federation dedups on UUID, so the row `id` remains the authoritative
/// 1:1 key; the cid is a best-effort federation-resolution hint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageNode {
    /// The reached memory's UUID (authoritative identity).
    pub id: String,
    /// The reached memory's content-address, or `None` (see type docs).
    pub cid: Option<String>,
    /// The lineage relation on the edge that reached this node
    /// (`derived_from` / `reflects_on` / `derives_from`).
    pub relation: String,
    /// Hop distance from the query root (1 = a direct parent/child).
    pub depth: usize,
}

impl std::fmt::Display for MemoryLinkRelation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Default for MemoryLinkRelation {
    fn default() -> Self {
        Self::default_relation()
    }
}

impl std::str::FromStr for MemoryLinkRelation {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str(s).ok_or_else(|| {
            format!(
                "invalid memory_link relation '{s}' (expected one of: related_to, \
                 supersedes, contradicts, derived_from, reflects_on, derives_from, \
                 decomposes_into, depends_on, advances)"
            )
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryLink {
    pub source_id: String,
    pub target_id: String,
    /// v0.7.0 fix campaign R1-M4 — typed closed set. Round-trips with
    /// the `memory_links.relation` TEXT column via
    /// `MemoryLinkRelation::as_str` (write) / `from_str` (read). The
    /// SQL CHECK constraint added in migration 0023 enforces the same
    /// membership at the storage layer so direct-SQL writers cannot
    /// bypass the Rust validator.
    pub relation: MemoryLinkRelation,
    pub created_at: String,
    /// v0.7 H3 — optional 64-byte Ed25519 signature carried over the
    /// federation wire. `None` for legacy peers (pre-v0.7) that do not
    /// sign outbound links; receivers in that case land the row with
    /// `attest_level = "unsigned"`. When `Some`, it is verified against
    /// the public key associated with `observed_by` before insert.
    /// `skip_serializing_if` keeps the wire shape byte-identical to
    /// pre-H3 for unsigned rows so v0.6.x peers continue to deserialize
    /// without surprise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<u8>>,
    /// v0.7 H3 — agent_id that asserts this link. Mirrors the H2
    /// `SignableLink.observed_by` field. Required when `signature` is
    /// `Some` (it is the lookup key for the verifying public key);
    /// `None` is treated as "no claim" and short-circuits to unsigned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_by: Option<String>,
    /// v0.7 H3 — RFC3339 instant the link became true (matches the
    /// homonymous column in `memory_links`). Part of the signed bundle;
    /// must round-trip byte-identical with what the sender signed for
    /// verification to succeed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    /// v0.7 H3 — RFC3339 instant the link was invalidated, or `None` if
    /// still valid. Part of the signed bundle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    /// v0.7 H4 — attestation level for the row (`"unsigned"`,
    /// `"self_signed"`, `"peer_attested"`). Populated by readers that
    /// surface the `memory_links.attest_level` TEXT column (e.g.
    /// `db::get_links` for the `memory_get_links` MCP tool). Stays
    /// `None` on constructors that don't go through a DB read — those
    /// paths still feed `create_link_inbound` which derives the column
    /// value from the `attest_level: &str` parameter. The
    /// `skip_serializing_if` keeps the wire shape byte-identical to
    /// pre-v0.7 federation peers that don't carry the column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attest_level: Option<String>,
    /// v0.9.0 G13-mem (#1859) / v1.0.0 #2215 — the lineage-DAG content-id
    /// mirror columns (`memory_links.source_cid` / `.target_cid`). Each edge
    /// mirrors its endpoints' schema-v74 `memories.cid` AT LINK-CREATION TIME
    /// so a lineage traversal resolves stable node identity even after an
    /// endpoint is tombstoned. Carried on the wire so the Portability-v2
    /// envelope round-trips them losslessly (#2215 — the exporter twin of the
    /// import repopulation fix): `crate::storage::export_links` populates
    /// them, and `crate::portability::import` re-writes them into the
    /// destination's mirror columns. `None` on legacy edges, pre-v74
    /// endpoints, or rows written while `lineage_dag_enabled()` was OFF.
    /// Advisory-resolution only (COND 2, #1859): NOT part of the Ed25519
    /// `SignableLink` preimage, so carrying them is byte-compat with every
    /// shipped signature + federated peer. `skip_serializing_if` keeps the
    /// wire byte-identical for the common NULL-mirror row (and for the
    /// selective read paths that leave them `None`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_cid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_cid: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LinkBody {
    /// Canonical name. Aliased by `from` (S82's wire shape).
    #[serde(default)]
    pub source_id: Option<String>,
    /// `from` alias for `source_id`.
    #[serde(default)]
    pub from: Option<String>,
    /// Canonical name. Aliased by `to` (S82's wire shape).
    #[serde(default)]
    pub target_id: Option<String>,
    /// `to` alias for `target_id`.
    #[serde(default)]
    pub to: Option<String>,
    /// Canonical name. Aliased by `rel_type` (S82's wire shape).
    #[serde(default)]
    pub relation: Option<String>,
    /// `rel_type` alias for `relation`.
    #[serde(default)]
    pub rel_type: Option<String>,
}

impl LinkBody {
    /// Resolve the canonical (source_id, target_id, relation) tuple
    /// from the canonical fields or their aliases. Defaults relation
    /// to `related_to` when neither field is supplied.
    #[must_use]
    pub fn resolved(&self) -> (String, String, String) {
        let s = self
            .source_id
            .clone()
            .or_else(|| self.from.clone())
            .unwrap_or_default();
        let t = self
            .target_id
            .clone()
            .or_else(|| self.to.clone())
            .unwrap_or_default();
        let r = self
            .relation
            .clone()
            .or_else(|| self.rel_type.clone())
            .unwrap_or_else(default_relation);
        (s, t, r)
    }
}

fn default_relation() -> String {
    MemoryLinkRelation::RelatedTo.as_str().to_string()
}

/// Tag stamped on entity-typed memories so `(title, namespace)` can be
/// shared across regular memories and entities without ambiguity (Pillar
/// 2 / Stream B).
pub const ENTITY_TAG: &str = "entity";

/// Marker written to `metadata.kind` on entity-typed memories. The
/// db layer keys entity lookups off this field so the alias resolver
/// never returns a regular memory that happens to share a title with an
/// entity registered later.
pub const ENTITY_KIND: &str = "entity";

/// Resolved entity record returned by `db::entity_get_by_alias` and
/// embedded in the `db::entity_register` response (Pillar 2 / Stream B).
/// `aliases` is the full alias set for the entity, ordered by
/// `created_at ASC, alias ASC` for stable display.
#[derive(Debug, Clone, Serialize)]
pub struct EntityRecord {
    pub entity_id: String,
    pub canonical_name: String,
    pub namespace: String,
    pub aliases: Vec<String>,
}

/// Outcome of `db::entity_register`. `created` is `true` when a new
/// entity memory was inserted, `false` when an existing entity was
/// reused (idempotent re-registration that just merged new aliases into
/// the existing record).
#[derive(Debug, Clone, Serialize)]
pub struct EntityRegistration {
    pub entity_id: String,
    pub canonical_name: String,
    pub namespace: String,
    pub aliases: Vec<String>,
    pub created: bool,
}

/// Single row returned by `db::kg_timeline` (Pillar 2 / Stream C).
///
/// Captures one outbound assertion from a source memory: the
/// `target_id` and its `relation`, the temporal-validity window
/// (`valid_from` / `valid_until`), the agent that observed it
/// (`observed_by`), and the target's display fields (`title`,
/// `target_namespace`) for caller convenience. `valid_from` is the
/// authoritative ordering key — events with NULL `valid_from` are
/// excluded from the timeline by the query.
#[derive(Debug, Clone, Serialize)]
pub struct KgTimelineEvent {
    pub target_id: String,
    pub relation: String,
    pub valid_from: String,
    pub valid_until: Option<String>,
    pub observed_by: Option<String>,
    pub title: String,
    pub target_namespace: String,
}

/// One node returned by `db::kg_query` (Pillar 2 / Stream C —
/// `memory_kg_query`). Each node represents a memory reachable from the
/// query's source through one outbound link, carrying the link's
/// temporal-validity columns plus the target memory's display fields and
/// the traversal path. `depth` is the actual number of hops from the
/// source (1..=`KG_QUERY_MAX_SUPPORTED_DEPTH`); `path` is the
/// `src->mid->target` chain as discovered by the recursive CTE.
#[derive(Debug, Clone, Serialize)]
pub struct KgQueryNode {
    pub target_id: String,
    pub relation: String,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub observed_by: Option<String>,
    pub title: String,
    pub target_namespace: String,
    pub depth: usize,
    pub path: String,
}

/// One nearest-neighbor result from a `memory_check_duplicate` lookup
/// (Pillar 2 / Stream D). `similarity` is the cosine similarity in
/// `[-1.0, 1.0]`, rounded to three decimals at the response layer.
///
/// v1.0.0 #3350 — `similarity` is an `Option` because a match can be
/// established WITHOUT a comparable embedding: an exact
/// `(title, namespace)` collision is a hard, guaranteed duplicate whose
/// cosine distance may be unknown (or meaningless). `None` on the wire is
/// `null` — never `0.0`, which would read as "measured, and far apart".
#[derive(Debug, Clone, Serialize)]
pub struct DuplicateMatch {
    pub id: String,
    pub title: String,
    pub namespace: String,
    pub similarity: Option<f32>,
}

/// v1.0.0 #3350 — how a DETERMINED duplicate verdict was reached.
///
/// A closed vocabulary: the wire `reason` is exactly [`Self::as_str`], so a
/// caller can branch on the evidence rather than guess at it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DuplicateEvidence {
    /// The candidate's `embedding_document(title, content)` hashes
    /// byte-equal to a live row's. Embedding-independent.
    ExactContentHash,
    /// A live row already occupies the candidate's `(title, namespace)`
    /// slot. `memories` is UNIQUE on that pair, so a store WOULD collide —
    /// a guaranteed duplicate, established without any embedding.
    ExactTitleInNamespace,
    /// Decided by cosine similarity over the comparable candidate pool.
    EmbeddingCosine,
    /// No live row was in scope at all, so there is nothing to duplicate.
    /// This IS an evaluated verdict, not a degraded one.
    EmptyCandidatePool,
}

impl DuplicateEvidence {
    /// The wire spelling of this evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExactContentHash => "exact_content_hash",
            Self::ExactTitleInNamespace => "exact_title_in_namespace",
            Self::EmbeddingCosine => "embedding_cosine",
            Self::EmptyCandidatePool => "empty_candidate_pool",
        }
    }
}

/// v1.0.0 #3350 — why a duplicate check could NOT reach a verdict.
///
/// These are the states that used to be reported as a confident
/// `is_duplicate: false` — a fail-OPEN verdict that told a caller "safe to
/// write" when nothing had actually been compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DuplicateUndetermined {
    /// The candidate produced no query vector (the embedder is absent,
    /// degraded, or returned an empty embedding), so no cosine comparison
    /// was possible.
    QueryEmbeddingUnavailable,
    /// Live rows ARE in scope but none could be compared: each was missing an
    /// embedding, carried a different dimension, or belonged to a foreign
    /// embedding space (#2167 §9 cross-space gate).
    NoComparableCandidates,
}

impl DuplicateUndetermined {
    /// The wire spelling of this reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QueryEmbeddingUnavailable => "query_embedding_unavailable",
            Self::NoComparableCandidates => "no_comparable_candidates",
        }
    }

    /// Operator-facing sentence explaining what to do about it.
    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::QueryEmbeddingUnavailable => {
                "the candidate could not be embedded, so no similarity comparison ran; \
                 enable semantic tier or above and retry before treating this write as unique"
            }
            Self::NoComparableCandidates => {
                "live memories exist in this scope but none carried a comparable embedding \
                 (missing, wrong dimension, or a different embedding space); backfill \
                 embeddings and retry before treating this write as unique"
            }
        }
    }
}

/// v1.0.0 #3350 — the outcome of a duplicate check.
///
/// [`Self::Undetermined`] is a FIRST-CLASS outcome, not an error and not a
/// `false`. Before #3350 the check collapsed "I compared the pool and found
/// nothing close" and "I could not compare anything at all" into the same
/// `is_duplicate: false`, so a candidate whose embedding was unavailable —
/// or whose namespace held only foreign-space rows — read as a clean
/// "not a duplicate" and a caller would happily write a duplicate on top of
/// it. Making the third state unrepresentable-as-`false` is the control:
/// [`Self::as_bool`] returns `Option<bool>`, so every consumer has to decide
/// what to do when there is no verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "verdict", content = "reason")]
pub enum DuplicateVerdict {
    /// Evaluated: this candidate duplicates [`DuplicateCheck::nearest`].
    Duplicate(DuplicateEvidence),
    /// Evaluated: this candidate is not a duplicate.
    NotDuplicate(DuplicateEvidence),
    /// NOT evaluated — the check could not decide. Never report this as
    /// "not a duplicate".
    Undetermined(DuplicateUndetermined),
}

impl DuplicateVerdict {
    /// `Some(true)` / `Some(false)` for an evaluated verdict; `None` when the
    /// check could not decide.
    ///
    /// Deliberately NOT a bare `bool`: a caller that wants one has to spell
    /// out what "no verdict" means for it, which is the whole point of #3350.
    #[must_use]
    pub const fn as_bool(self) -> Option<bool> {
        match self {
            Self::Duplicate(_) => Some(true),
            Self::NotDuplicate(_) => Some(false),
            Self::Undetermined(_) => None,
        }
    }

    /// `true` when the check reached a verdict.
    #[must_use]
    pub const fn is_determined(self) -> bool {
        self.as_bool().is_some()
    }

    /// Wire `status`: `"ok"` for an evaluated verdict, `"degraded"` when the
    /// check could not decide.
    #[must_use]
    pub const fn status(self) -> &'static str {
        if self.is_determined() {
            "ok"
        } else {
            "degraded"
        }
    }

    /// Wire `reason` — the closed-vocabulary token naming the evidence
    /// behind the verdict, or the reason no verdict was reached.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Duplicate(e) | Self::NotDuplicate(e) => e.as_str(),
            Self::Undetermined(u) => u.as_str(),
        }
    }

    /// Operator-facing detail for a degraded check; `None` when determined.
    #[must_use]
    pub const fn degraded_detail(self) -> Option<&'static str> {
        match self {
            Self::Undetermined(u) => Some(u.detail()),
            _ => None,
        }
    }
}

/// Result envelope returned by `db::check_duplicate`.
///
/// `nearest.id` doubles as the suggested merge target when the verdict is
/// [`DuplicateVerdict::Duplicate`] — we surface it under that name in the
/// JSON response so the contract stays explicit.
///
/// v1.0.0 #3350 — the boolean `is_duplicate` field became
/// [`DuplicateCheck::verdict`], and `candidates_available` joined
/// `candidates_scanned`. The pair is what makes a degraded check *visible*:
/// `scanned == 0 && available == 0` means "nothing was in scope" (an honest
/// not-a-duplicate), while `scanned == 0 && available > 0` means "rows were
/// in scope and NONE of them could be compared" — which used to be reported
/// as the same confident `false`.
#[derive(Debug, Clone, Serialize)]
pub struct DuplicateCheck {
    pub verdict: DuplicateVerdict,
    pub threshold: f32,
    pub nearest: Option<DuplicateMatch>,
    /// Candidates actually COMPARED (hash-compared, or cosine-compared).
    pub candidates_scanned: usize,
    /// Live rows in scope (after the namespace filter), comparable or not.
    pub candidates_available: usize,
}

/// One node of the hierarchical namespace tree returned by
/// `memory_get_taxonomy` (Pillar 1 / Stream A).
///
/// `count` is the number of memories at *exactly* this namespace;
/// `subtree_count` is the count of memories at this node plus every
/// descendant the depth limit allowed us to expand. Children are sorted
/// alphabetically by `name` so callers get a stable rendering order.
#[derive(Debug, Clone, Serialize)]
pub struct TaxonomyNode {
    /// Full namespace path of this node. Empty string for the synthetic
    /// root when no `namespace_prefix` is supplied.
    pub namespace: String,
    /// Last `/`-delimited segment of `namespace` (display label). Empty
    /// for the synthetic root.
    pub name: String,
    /// Memories whose namespace equals this node's `namespace`.
    pub count: usize,
    /// Memories at this node plus all descendants visible within the
    /// requested `depth`. Memories beneath the depth cutoff still
    /// contribute to the `subtree_count` of the boundary ancestor.
    pub subtree_count: usize,
    /// Direct child nodes, sorted alphabetically by `name`.
    pub children: Vec<TaxonomyNode>,
}

/// Result envelope returned by `db::get_taxonomy`.
///
/// `total_count` is the global memory count for the prefix (independent
/// of `depth`/`limit` truncation) so callers can render an honest
/// "X memories in N namespaces" header even when the tree was
/// truncated. `truncated` is set when the `limit` parameter forced us
/// to drop input rows when assembling the tree.
#[derive(Debug, Clone, Serialize)]
pub struct Taxonomy {
    pub tree: TaxonomyNode,
    pub total_count: usize,
    pub truncated: bool,
}

/// Phase 3 foundation (issue #224): vector clock tracking the latest
/// `updated_at` this peer has seen from each known remote peer.
///
/// Entries are populated lazily — both on HTTP `/sync/push` (receiver
/// records the sender's latest `updated_at`) and on HTTP `/sync/since`
/// (sender advances `last_pulled_at`). Full CRDT-lite merge rules using
/// the clock are **not** in the v0.6.0 GA foundation; they land in a
/// follow-up PR under issue #224 Task 3a.1. The foundation ships the
/// wire format so adding the merge semantics later does not force a
/// schema migration.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct VectorClock {
    /// Map of peer `agent_id` -> latest RFC3339 `updated_at` seen from
    /// that peer. A peer absent from the map is equivalent to
    /// "never-seen-anything." Encoded as a JSON object on the wire.
    #[serde(default)]
    pub entries: std::collections::BTreeMap<String, String>,
}

/// The causal relationship between two [`VectorClock`]s, as returned by
/// [`VectorClock::causality`].
///
/// v0.8.0 Pillar-3 (CRDT/consensus, #1709) / #224 Task 3a.1 CRDT-lite
/// merge. This is the canonical comparator for the sync-state vector
/// clock: every higher-level predicate
/// ([`VectorClock::happens_before`], [`VectorClock::concurrent_with`])
/// is derived from it, so there is exactly one source of truth for the
/// causality decision.
///
/// `HappensBefore` means `self` is causally dominated by `other`
/// (`other` has seen everything `self` has, strictly more). `Concurrent`
/// means the two clocks have diverged — each has observed a peer
/// timestamp the other has not caught up on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Causality {
    /// The two clocks carry identical per-peer timestamps.
    Equal,
    /// `self` is strictly causally dominated by `other`.
    HappensBefore,
    /// `self` strictly causally dominates `other`.
    HappensAfter,
    /// The clocks have diverged; neither dominates the other.
    Concurrent,
}

impl VectorClock {
    /// Advance this clock to include `peer_id`'s latest seen timestamp.
    /// Monotonic — an older timestamp never overwrites a newer one.
    pub fn observe(&mut self, peer_id: &str, at: &str) {
        self.entries
            .entry(peer_id.to_string())
            .and_modify(|existing| {
                if at > existing.as_str() {
                    *existing = at.to_string();
                }
            })
            .or_insert_with(|| at.to_string());
    }

    /// Look up the latest timestamp this clock has from `peer_id`.
    #[must_use]
    pub fn latest_from(&self, peer_id: &str) -> Option<&str> {
        self.entries.get(peer_id).map(String::as_str)
    }

    /// The timestamp this clock carries for `peer_id`, treating a peer
    /// ABSENT from `entries` as the minimal timestamp (`""` — the empty
    /// string sorts before every RFC3339 value, i.e. "never seen").
    ///
    /// Comparison is lexical, mirroring [`VectorClock::observe`] exactly
    /// (the existing string-`max` convention; timestamps are NOT parsed
    /// to `DateTime`). Callers therefore rely on the same zero-padded,
    /// same-offset RFC3339 encoding the rest of the substrate emits.
    #[must_use]
    fn at(&self, peer_id: &str) -> &str {
        self.entries.get(peer_id).map_or("", String::as_str)
    }

    /// v0.8.0 Pillar-3 (#1709) / #224 Task 3a.1 — pointwise-max merge.
    ///
    /// For every peer present in `other`, set
    /// `self[peer] = max(self[peer], other[peer])` by lexical RFC3339
    /// comparison (the [`VectorClock::observe`] rule). Peers only in
    /// `self` are retained; the result is the union of both peer sets
    /// with each entry advanced to the later timestamp. An older
    /// `other` timestamp never regresses a newer `self` entry.
    ///
    /// This is the load-bearing reconciliation primitive: it is
    /// idempotent (`merge(x, x) == x`), commutative (the merged clock is
    /// independent of order), and associative.
    pub fn merge(&mut self, other: &VectorClock) {
        for (peer, at) in &other.entries {
            self.observe(peer, at);
        }
    }

    /// v0.8.0 Pillar-3 (#1709) / #224 Task 3a.1 — the canonical
    /// causality comparator. Every other predicate on this type is
    /// derived from this one method so the logic cannot diverge.
    ///
    /// Returns [`Causality::Equal`] when the two clocks carry identical
    /// per-peer timestamps; [`Causality::HappensBefore`] when `other`
    /// strictly dominates `self` (`self[p] <= other[p]` for every peer
    /// in either clock, and they are not equal);
    /// [`Causality::HappensAfter`] for the mirror; and
    /// [`Causality::Concurrent`] when neither dominates the other (each
    /// is ahead on some peer). Absent peers are treated as the minimal
    /// timestamp, so an empty clock happens-before any non-empty clock.
    #[must_use]
    pub fn causality(&self, other: &VectorClock) -> Causality {
        if self == other {
            return Causality::Equal;
        }
        // `self` is dominated by `other` iff no peer (in either clock)
        // has a strictly-greater timestamp in `self` than in `other`.
        let mut self_le_other = true; // self <= other pointwise
        let mut other_le_self = true; // other <= self pointwise
        for peer in self.entries.keys().chain(other.entries.keys()) {
            let s = self.at(peer);
            let o = other.at(peer);
            if s > o {
                self_le_other = false;
            }
            if o > s {
                other_le_self = false;
            }
        }
        match (self_le_other, other_le_self) {
            // Equality is handled above, so both-true is unreachable
            // here; fold it into Equal defensively rather than panic.
            (true, true) => Causality::Equal,
            (true, false) => Causality::HappensBefore,
            (false, true) => Causality::HappensAfter,
            (false, false) => Causality::Concurrent,
        }
    }

    /// v0.8.0 Pillar-3 (#1709) / #224 Task 3a.1 — strict causal
    /// dominance: true iff `other` strictly dominates `self` (for every
    /// peer `p`, `self[p] <= other[p]`, and `self != other`). Derived
    /// from [`VectorClock::causality`] (single source of truth).
    #[must_use]
    pub fn happens_before(&self, other: &VectorClock) -> bool {
        self.causality(other) == Causality::HappensBefore
    }

    /// v0.8.0 Pillar-3 (#1709) / #224 Task 3a.1 — concurrency: true iff
    /// the two clocks have diverged (neither happens-before the other
    /// and they are not equal). Derived from [`VectorClock::causality`].
    #[must_use]
    pub fn concurrent_with(&self, other: &VectorClock) -> bool {
        self.causality(other) == Causality::Concurrent
    }
}

/// Phase 3 foundation: one row of the `sync_state` table serialised for
/// diagnostic / API responses.
#[allow(dead_code)] // Consumed by Task 3b.2 sync diagnostics API (issue #224).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStateEntry {
    pub agent_id: String,
    pub peer_id: String,
    pub last_seen_at: String,
    pub last_pulled_at: String,
}

// -----------------------------------------------------------------
// L0.7-2 Tier A — LinkBody alias + AttestLevel + VectorClock coverage
// -----------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn parse_link_body(json: serde_json::Value) -> LinkBody {
        serde_json::from_value(json).expect("LinkBody deserialises")
    }

    #[test]
    fn link_body_resolved_uses_canonical_fields_when_present() {
        let b = parse_link_body(serde_json::json!({
            "source_id": "src",
            "target_id": "tgt",
            "relation": "supersedes",
        }));
        let (s, t, r) = b.resolved();
        assert_eq!(s, "src");
        assert_eq!(t, "tgt");
        assert_eq!(r, "supersedes");
    }

    #[test]
    fn link_body_resolved_falls_back_to_from_alias() {
        // Line 135: from-alias path for source_id
        let b = parse_link_body(serde_json::json!({
            "from": "from-id",
            "to": "to-id",
            "rel_type": "contradicts",
        }));
        let (s, t, r) = b.resolved();
        assert_eq!(s, "from-id");
        assert_eq!(t, "to-id");
        assert_eq!(r, "contradicts");
    }

    #[test]
    fn link_body_resolved_defaults_relation_to_related_to() {
        // Lines 145, 151-153: default_relation invoked when neither
        // `relation` nor `rel_type` set.
        let b = parse_link_body(serde_json::json!({
            "source_id": "a",
            "target_id": "b",
        }));
        let (_s, _t, r) = b.resolved();
        assert_eq!(r, "related_to");
    }

    #[test]
    fn link_body_resolved_empty_payload_returns_empty_strings_and_default() {
        let b = parse_link_body(serde_json::json!({}));
        let (s, t, r) = b.resolved();
        assert_eq!(s, "");
        assert_eq!(t, "");
        assert_eq!(r, "related_to");
    }

    #[test]
    fn link_body_resolved_canonical_wins_over_alias() {
        // When BOTH canonical and alias are set, the canonical wins.
        let b = parse_link_body(serde_json::json!({
            "source_id": "canonical-src",
            "from": "alias-src",
            "target_id": "canonical-tgt",
            "to": "alias-tgt",
            "relation": "canonical-rel",
            "rel_type": "alias-rel",
        }));
        let (s, t, r) = b.resolved();
        assert_eq!(s, "canonical-src");
        assert_eq!(t, "canonical-tgt");
        assert_eq!(r, "canonical-rel");
    }

    #[test]
    fn attest_level_round_trips_strings() {
        for (s, v) in [
            ("unsigned", AttestLevel::Unsigned),
            ("self_signed", AttestLevel::SelfSigned),
            ("peer_attested", AttestLevel::PeerAttested),
        ] {
            assert_eq!(AttestLevel::from_str(s), Some(v));
            assert_eq!(v.as_str(), s);
            assert_eq!(format!("{v}"), s);
        }
    }

    #[test]
    fn attest_level_from_str_returns_none_for_unknown() {
        assert_eq!(AttestLevel::from_str("unknown"), None);
        assert_eq!(AttestLevel::from_str(""), None);
    }

    #[test]
    fn vector_clock_observe_advances_monotonically() {
        let mut c = VectorClock::default();
        c.observe("peer-a", "2026-01-01T00:00:00Z");
        assert_eq!(c.latest_from("peer-a"), Some("2026-01-01T00:00:00Z"));
        // Later timestamp must replace.
        c.observe("peer-a", "2026-02-01T00:00:00Z");
        assert_eq!(c.latest_from("peer-a"), Some("2026-02-01T00:00:00Z"));
        // Earlier timestamp must NOT replace.
        c.observe("peer-a", "2025-12-01T00:00:00Z");
        assert_eq!(c.latest_from("peer-a"), Some("2026-02-01T00:00:00Z"));
    }

    #[test]
    fn vector_clock_latest_from_unknown_peer_is_none() {
        let c = VectorClock::default();
        assert_eq!(c.latest_from("never-seen"), None);
    }

    #[test]
    fn vector_clock_serializes_as_object_with_entries() {
        let mut c = VectorClock::default();
        c.observe("peer-a", "2026-01-01T00:00:00Z");
        let json = serde_json::to_value(&c).unwrap();
        assert!(json.get("entries").is_some());
        assert_eq!(
            json["entries"]["peer-a"],
            serde_json::Value::String("2026-01-01T00:00:00Z".to_string())
        );
    }

    // ---- v0.8.0 Pillar-3 (#1709) / #224 Task 3a.1 — VectorClock
    // causality algebra + merge. Pure, deterministic truth table. ----

    /// Build a clock from `(peer, timestamp)` pairs for the algebra tests.
    fn vc(pairs: &[(&str, &str)]) -> VectorClock {
        let mut c = VectorClock::default();
        for (p, at) in pairs {
            c.observe(p, at);
        }
        c
    }

    #[test]
    fn vector_clock_causality_identical_clocks_are_equal() {
        let a = vc(&[
            ("p1", "2026-01-01T00:00:00Z"),
            ("p2", "2026-02-01T00:00:00Z"),
        ]);
        let b = a.clone();
        assert_eq!(a.causality(&b), Causality::Equal);
        assert!(!a.happens_before(&b));
        assert!(!a.concurrent_with(&b));
    }

    #[test]
    fn vector_clock_causality_strict_superset_happens_after() {
        // `b` has seen everything `a` has, plus more → a < b, b > a.
        let a = vc(&[("p1", "2026-01-01T00:00:00Z")]);
        let b = vc(&[
            ("p1", "2026-01-01T00:00:00Z"),
            ("p2", "2026-01-01T00:00:00Z"),
        ]);
        assert_eq!(a.causality(&b), Causality::HappensBefore);
        assert_eq!(b.causality(&a), Causality::HappensAfter);
        assert!(a.happens_before(&b));
        assert!(!b.happens_before(&a));
        assert!(!a.concurrent_with(&b));
    }

    #[test]
    fn vector_clock_causality_newer_timestamp_same_peer_happens_after() {
        let a = vc(&[("p1", "2026-01-01T00:00:00Z")]);
        let b = vc(&[("p1", "2026-02-01T00:00:00Z")]);
        assert_eq!(a.causality(&b), Causality::HappensBefore);
        assert_eq!(b.causality(&a), Causality::HappensAfter);
    }

    #[test]
    fn vector_clock_causality_divergent_clocks_are_concurrent() {
        // Each clock is ahead on a peer the other has not caught up on.
        let a = vc(&[
            ("p1", "2026-02-01T00:00:00Z"),
            ("p2", "2026-01-01T00:00:00Z"),
        ]);
        let b = vc(&[
            ("p1", "2026-01-01T00:00:00Z"),
            ("p2", "2026-02-01T00:00:00Z"),
        ]);
        assert_eq!(a.causality(&b), Causality::Concurrent);
        assert_eq!(b.causality(&a), Causality::Concurrent);
        assert!(a.concurrent_with(&b));
        assert!(b.concurrent_with(&a));
        assert!(!a.happens_before(&b));
        assert!(!b.happens_before(&a));
    }

    #[test]
    fn vector_clock_causality_empty_vs_nonempty() {
        let empty = VectorClock::default();
        let some = vc(&[("p1", "2026-01-01T00:00:00Z")]);
        // Absent peer is the minimal timestamp → empty happens-before.
        assert_eq!(empty.causality(&some), Causality::HappensBefore);
        assert_eq!(some.causality(&empty), Causality::HappensAfter);
        assert!(empty.happens_before(&some));
        // Two empty clocks are equal, never concurrent.
        let empty2 = VectorClock::default();
        assert_eq!(empty.causality(&empty2), Causality::Equal);
        assert!(!empty.concurrent_with(&empty2));
    }

    #[test]
    fn vector_clock_absent_peer_is_minimal_not_concurrent() {
        // p2 absent in `a` is treated as minimal, so `a` < `b` rather
        // than concurrent (b only advances on the absent peer).
        let a = vc(&[("p1", "2026-01-01T00:00:00Z")]);
        let b = vc(&[
            ("p1", "2026-01-01T00:00:00Z"),
            ("p2", "2026-01-01T00:00:00Z"),
        ]);
        assert!(a.happens_before(&b));
        assert!(!a.concurrent_with(&b));
    }

    #[test]
    fn vector_clock_merge_is_pointwise_max() {
        let mut a = vc(&[
            ("p1", "2026-01-01T00:00:00Z"),
            ("p2", "2026-03-01T00:00:00Z"),
        ]);
        let b = vc(&[
            ("p1", "2026-02-01T00:00:00Z"), // newer on p1 → wins
            ("p2", "2026-01-01T00:00:00Z"), // older on p2 → must NOT regress
            ("p3", "2026-01-01T00:00:00Z"), // new peer → added
        ]);
        a.merge(&b);
        assert_eq!(a.latest_from("p1"), Some("2026-02-01T00:00:00Z"));
        assert_eq!(a.latest_from("p2"), Some("2026-03-01T00:00:00Z"));
        assert_eq!(a.latest_from("p3"), Some("2026-01-01T00:00:00Z"));
    }

    #[test]
    fn vector_clock_merge_is_idempotent() {
        let a = vc(&[
            ("p1", "2026-01-01T00:00:00Z"),
            ("p2", "2026-02-01T00:00:00Z"),
        ]);
        let mut once = a.clone();
        once.merge(&a);
        assert_eq!(once, a, "merge(x, x) == x");
    }

    #[test]
    fn vector_clock_merge_is_commutative() {
        let a = vc(&[
            ("p1", "2026-02-01T00:00:00Z"),
            ("p2", "2026-01-01T00:00:00Z"),
        ]);
        let b = vc(&[
            ("p1", "2026-01-01T00:00:00Z"),
            ("p3", "2026-05-01T00:00:00Z"),
        ]);
        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);
        assert_eq!(ab, ba, "merge order must not change the result");
    }

    #[test]
    fn vector_clock_merge_is_associative() {
        let a = vc(&[("p1", "2026-01-01T00:00:00Z")]);
        let b = vc(&[
            ("p1", "2026-02-01T00:00:00Z"),
            ("p2", "2026-01-01T00:00:00Z"),
        ]);
        let c = vc(&[
            ("p2", "2026-03-01T00:00:00Z"),
            ("p3", "2026-01-01T00:00:00Z"),
        ]);
        // (a ∪ b) ∪ c
        let mut left = a.clone();
        left.merge(&b);
        left.merge(&c);
        // a ∪ (b ∪ c)
        let mut bc = b.clone();
        bc.merge(&c);
        let mut right = a.clone();
        right.merge(&bc);
        assert_eq!(left, right, "merge must be associative");
    }

    #[test]
    fn vector_clock_merge_result_dominates_both_inputs() {
        // The merged clock causally dominates (or equals) each input —
        // the algebra and merge agree.
        let a = vc(&[
            ("p1", "2026-02-01T00:00:00Z"),
            ("p2", "2026-01-01T00:00:00Z"),
        ]);
        let b = vc(&[
            ("p1", "2026-01-01T00:00:00Z"),
            ("p2", "2026-02-01T00:00:00Z"),
        ]);
        // a and b are concurrent, but their merge is after both.
        assert!(a.concurrent_with(&b));
        let mut m = a.clone();
        m.merge(&b);
        assert_eq!(a.causality(&m), Causality::HappensBefore);
        assert_eq!(b.causality(&m), Causality::HappensBefore);
        assert_eq!(m.causality(&m), Causality::Equal);
    }

    // ---- C-5 (#699): lift coverage on MemoryLinkRelation parsing/defaults.
    // Targets uncovered: `MemoryLinkRelation::from_str` unknown branch,
    // `default_relation`, `Default::default`, `FromStr` wrapper. ----

    #[test]
    fn memory_link_relation_from_str_returns_none_for_unknown() {
        // Line 116: `_ => None` arm of the inherent from_str.
        assert_eq!(MemoryLinkRelation::from_str("bogus"), None);
        assert_eq!(MemoryLinkRelation::from_str(""), None);
        assert_eq!(MemoryLinkRelation::from_str("RELATED_TO"), None);
    }

    #[test]
    fn memory_link_relation_default_relation_is_related_to() {
        // Lines 138-140: `default_relation()` associated function.
        let d = MemoryLinkRelation::default_relation();
        assert_eq!(d, MemoryLinkRelation::RelatedTo);
        assert_eq!(d.as_str(), "related_to");
    }

    #[test]
    fn memory_link_relation_default_trait_uses_related_to() {
        // Lines 150-152: `Default::default()` implementation.
        let d: MemoryLinkRelation = Default::default();
        assert_eq!(d, MemoryLinkRelation::RelatedTo);
    }

    #[test]
    fn memory_link_relation_from_str_trait_round_trips_canonical_strings() {
        // Lines 158-165: `std::str::FromStr::from_str` wrapper.
        for (s, v) in [
            ("related_to", MemoryLinkRelation::RelatedTo),
            ("supersedes", MemoryLinkRelation::Supersedes),
            ("contradicts", MemoryLinkRelation::Contradicts),
            ("derived_from", MemoryLinkRelation::DerivedFrom),
            ("reflects_on", MemoryLinkRelation::ReflectsOn),
            ("derives_from", MemoryLinkRelation::DerivesFrom),
            ("decomposes_into", MemoryLinkRelation::DecomposesInto),
            ("depends_on", MemoryLinkRelation::DependsOn),
            ("advances", MemoryLinkRelation::Advances),
        ] {
            // Disambiguate against the inherent `from_str` (which returns
            // Option) by going through the `FromStr` trait fully qualified.
            let parsed: MemoryLinkRelation =
                <MemoryLinkRelation as std::str::FromStr>::from_str(s).unwrap();
            assert_eq!(parsed, v);
            // Display impl round-trip.
            assert_eq!(format!("{v}"), s);
        }
    }

    #[test]
    fn memory_link_relation_typed_cognition_relations_round_trip() {
        // v0.8.0 Pillar-2 (#1709) — the Goal/Plan/Step wiring relations
        // round-trip through as_str/from_str, are enumerated by all(),
        // and never displace the RelatedTo default.
        for (s, v) in [
            ("decomposes_into", MemoryLinkRelation::DecomposesInto),
            ("depends_on", MemoryLinkRelation::DependsOn),
            ("advances", MemoryLinkRelation::Advances),
        ] {
            assert_eq!(MemoryLinkRelation::from_str(s), Some(v));
            assert_eq!(v.as_str(), s);
            assert_eq!(format!("{v}"), s);
            assert!(
                MemoryLinkRelation::all().contains(&v),
                "all() must enumerate the typed-cognition variant {v:?}"
            );
        }
        // Unknown still returns None and the default is unchanged.
        assert_eq!(MemoryLinkRelation::from_str("decomposes"), None);
        assert_eq!(MemoryLinkRelation::from_str("advance"), None);
        assert_eq!(MemoryLinkRelation::default(), MemoryLinkRelation::RelatedTo);
        assert_eq!(MemoryLinkRelation::all().len(), MemoryLinkRelation::COUNT);
        assert_eq!(MemoryLinkRelation::COUNT, 9);
    }

    #[test]
    fn memory_link_relation_from_str_trait_returns_helpful_error_for_unknown() {
        // Lines 158-165: error arm of the FromStr wrapper.
        let err = <MemoryLinkRelation as std::str::FromStr>::from_str("nope").unwrap_err();
        assert!(err.contains("nope"));
        assert!(err.contains("related_to"));
        assert!(err.contains("reflects_on"));
    }
}
