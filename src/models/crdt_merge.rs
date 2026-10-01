// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 Pillar-3 (#1709 / #224) — CRDT-lite per-field memory merge.
//!
//! [`merge_memory`] is a **pure, deterministic** field-wise reconciler:
//! given two divergent same-`id` [`Memory`] rows (a `local` and a
//! `remote`/peer replica) it produces a single merged row by applying
//! the canonical #224 design-table rule to each field independently.
//!
//! ## Why CRDT-lite
//!
//! The substrate's pre-existing federation conflict path
//! (`storage::insert_if_newer`) resolves a `(title, namespace)`
//! collision by whole-column newer-wins inside one SQL `ON CONFLICT`
//! statement: scalar last-write-wins for most columns, with a handful
//! of `MAX(...)` / `COALESCE(...)` arms. That is a *coarse* merge —
//! `tags` are REPLACED, not unioned, and `metadata` is preserved only
//! for `agent_id`. The #224 design table specifies a *finer* merge
//! where each field carries the resolution rule that preserves the
//! most information (union, max, min, deep-JSON-merge), so two agents
//! that each appended a distinct tag both keep their tag after the
//! merge.
//!
//! [`merge_memory`] implements that finer table as a free function over
//! two in-memory [`Memory`] values, with **no I/O and no clock reads**
//! — it never calls `Utc::now()` and never touches the database, so it
//! is trivially testable and replayable. Wiring it into the SQL
//! conflict path is a *separate* unit (the SQL upsert would have to
//! become a read-merge-write transaction); this module lands the pure
//! reconciler + its exhaustive per-rule test suite.
//!
//! ## Determinism / algebraic properties
//!
//! Every "last-write-wins" (LWW) resolution tiebreaks on the total
//! order `(updated_at, attest_rank, id)` (#1719 item 3a) — strictly
//! newer `updated_at` wins; on an `updated_at` tie the higher
//! attestation rank wins (a verified `agent_attested` row beats an
//! unsigned `claimed` one); and only on a further tie does the
//! lexically-greater `id` break it. Because the tiebreak is a *total
//! order over the two operands* (never "keep the first argument"),
//! `merge_memory` is:
//!
//! * **commutative** — `merge(a, b)` and `merge(b, a)` serialise
//!   identically (max / min / union are order-free; LWW picks the same
//!   `(updated_at, attest_rank, id)`-maximal side regardless of argument
//!   position);
//! * **idempotent** — `merge(a, a) == a`;
//! * **associative** on the commutative fields (max/min/union) and on
//!   the LWW fields (which all collapse to the global
//!   `(updated_at, attest_rank, id)`-maximal operand).
//!
//! The `attest_rank` middle key is trustworthy only because the
//! federation merge boundary (`merge_inbound`) calls
//! [`sanitize_inbound_attestation`] on the untrusted remote first, so a
//! peer cannot win the tiebreak by self-asserting a verified level — see
//! that function's docs and #1755 (3b) for the `updated_at`-postdating
//! residual.
//!
//! These are the convergence properties a CRDT needs: peers that
//! receive the same set of replicas in any order reach the same state.
//!
//! **What makes the associativity claim true (v1.0.0 #4030 / #4031):**
//! every timestamp is ordered by INSTANT, never by string
//! ([`super::crdt_field_clock::temporal_cmp`]), so the content winner and
//! the stamped `updated_at` always agree; and a value RETAINED from an
//! operand the other side lacked keeps its OWN version (the per-path
//! clocks in `metadata.crdt_field_clocks`) instead of inheriting the merged
//! row's newer clock. **Documented exceptions:** the node-local fields
//! (`agent_id`, `governance`, `valid_from`, `cid`, the node-local metadata
//! keys, the containment lifecycle overlay) are local-wins by design, and an
//! exactly-equal `(updated_at, attest_rank)` pair with different content is
//! the #344 same-clock residual. **Bounded (#4032):** the tag union and the
//! metadata join are capped at the replicated-state limits every receiver
//! validates against; past a cap the join degrades deterministically (see
//! `merge_tags` / `merge_memory`), WARNed on [`CRDT_BOUND_TRACE_TARGET`].
//! The tag bound ("the k smallest of the union") is itself a join, so it
//! stays associative. The METADATA bound is NOT: its fallback (the row-LWW
//! winner's ordinary keys) depends on which intermediate join first crossed
//! the byte cap, so replicas that join over-cap rows in different orders can
//! keep different subsets of the LOSING operands' disjoint keys. That is the
//! documented residual of a byte-bounded map (sizes differ per key, so no
//! byte-bounded selection is a join); it is reachable only past the 512 KiB
//! replicated cap, every drop is WARNed and the pre-merge row survives in the
//! `federation_merge` archive snapshot. The visibility keys
//! (`VISIBILITY_METADATA_KEYS`) are exempt from the fallback and always
//! resolve through the full per-path join, so the residual never changes who
//! can read a row.
//!
//! **Equal-clock residuals (extend #344; stated precisely).** Every claim
//! above is for operands with DISTINCT `(updated_at, attest_rank)`. The `id`
//! tie-break is inert inside `merge_memory` (both operands share the id), so
//! at an exactly equal `(updated_at, attest_rank)`:
//! * the metadata bounded fallback is NOT commutative — neither side "wins"
//!   the row-LWW order, so the LOCAL operand's ordinary keys are kept in
//!   both argument orders (`L@5{k1}` vs `R@5{k2}` keeps `k1` on L's node and
//!   `k2` on R's);
//! * an object/scalar flip at the same microsecond is not associative (the
//!   flip is decided by `(version, rank, fingerprint)`, and which floor is
//!   recorded depends on grouping);
//! * the visibility keys fail CLOSED at a tie: at an equal VERSION an absence
//!   beats any presence, whatever the attestation rank of either row, and two
//!   different PRESENT `scope` values resolve to the NARROWER one (an
//!   unrecognised or non-string value, then `private`, `team`, `unit`, `org`,
//!   and `collective` / the legacy broad set last), so an equal-microsecond
//!   `private` vs `collective` ends private in every grouping; only the
//!   agent-id keys, which have no narrowness order, fall to the value
//!   fingerprint (deterministic, not "most restrictive"). The visibility
//!   register compares `(version, narrowness, fingerprint)` and never the rank
//!   because the rank is read from the MERGED row's `attest_level`: a value
//!   that landed in an attested row would carry rank 1 into the next merge and
//!   the verdict would then depend on the merge grouping (f2r, rank
//!   laundering; cell
//!   `pure_visibility_register_never_fails_open_by_grouping_rank_laundering`).
//!   The register applies to EVERY value shape: an object at a visibility key
//!   is an opaque register value, never routed to the generic join (r11 F1:
//!   there a one-sided presence survives and a later scalar beats the object);
//! * the same rank laundering leaves an associativity residual for the
//!   NON-visibility keys at an equal clock: with `a = {u:20, k:"x"}`,
//!   `b = {u:20, attested}` and `c = {u:21, k:"y", leaf /k@20}`, `(a|b)|c`
//!   keeps `"x"` while the other groupings keep `"y"`. Ordinary data only, it
//!   never changes who can read a row.
//!
//! **Share revocation by an unrelated newer row (availability, fail closed).**
//! A MISSING visibility key is dated at its row's clock, so any peer row newer
//! than a share's own version revokes that share even when the peer never
//! received it: local `{u:34, target_agent_id:"bob"@22, scope:"collective"@22}`
//! merged with `{u:31, note:"y"}` loses both keys in both orders (plain
//! row-LWW would have kept them). This is the design: an absence is a
//! statement "as of this clock", so the merge can only narrow, never widen.
//! It is operator-visible: a share made on one node can be revoked by an
//! unrelated concurrent edit on a node that never saw it. To recover, the
//! owner re-shares (a new write of `scope` / `target_agent_id` carries a fresh
//! version that beats every older absence).
//!
//! **Clock-map bytes are not convergent.** The merged VALUES converge; the
//! reserved `metadata.crdt_field_clocks` object can differ in BYTES between
//! replicas that joined the same rows in different groupings:
//! a leaf is recorded only when a retained value is older than that join's
//! row clock, and floors are recorded per join. Anything that compares whole
//! metadata objects to detect a USER edit (for example the #4216 merge
//! version bump) MUST exclude `crdt_field_clocks` and `version_vector`, or it
//! will report a change no user made.
//!
//! ## Metadata sub-rules (#224 + Task 1.8 #196)
//!
//! `metadata` is a deep JSON merge (objects merge key-wise recursively;
//! disjoint keys both survive; non-object collisions fall back to LWW),
//! with four overrides applied AFTER the deep merge:
//!
//! * `metadata.agent_id` — **immutable, original (`local`) wins**
//!   (NHI provenance is write-once; a peer must not rewrite it).
//! * `metadata.scope`, `metadata.target_agent_id`,
//!   `metadata.recipient_agent_id` (the visibility keys) — per-key LWW by the
//!   key's own version (#4031), where ABSENCE is a versioned value too (f2r
//!   review): an owner makes a row private by dropping `scope` and revokes a
//!   share by dropping `target_agent_id`, so a NEWER absence beats an OLDER
//!   presence. This is the one deliberate exception to "absence is never a
//!   deletion": preserving a stale visibility value would re-widen a row its
//!   owner narrowed.
//! * `metadata.governance` — **keep `local`'s** (owner-only override; a
//!   merge must never let a peer rewrite governance).
//! * `metadata.version_vector` — **pointwise-max [`VectorClock`] merge**
//!   (#1756 / #1719 item 2): the per-memory CRDT clock must join by
//!   per-peer max, NOT the default deep-merge/LWW (which would discard a
//!   peer observation carried by the row that lost the row-level LWW).
//!   Carried + merged only at this milestone — not yet read to gate a
//!   dominant-side discard (#1709 ship-but-don't-gate).

use serde_json::{Map, Value};

use super::crdt_field_clock::FieldClockMerge;
use super::crdt_primitives::{OrSet, PnCounter};
use super::field_names;
use super::link::VectorClock;
use super::memory::{LifecycleState, Memory};
use crate::identity::verify::AttestLevel;
use crate::mcp::param_names;

/// #1756 / #1719 item 2 — extract a row's per-memory CRDT vector clock
/// from its `metadata.version_vector` key. An absent or malformed value
/// yields the empty clock (`VectorClock::default()`), which is the
/// minimal lattice element ("never observed anything") — so legacy rows
/// that predate the clock merge byte-identically to today.
fn parse_version_vector(metadata: &Value) -> VectorClock {
    metadata
        .get(field_names::VERSION_VECTOR)
        .and_then(|v| serde_json::from_value::<VectorClock>(v.clone()).ok())
        .unwrap_or_default()
}

/// #1757 / #1719 item 2b — advance the LOCAL node's component of a row's
/// per-memory vector clock at local-authorship write time, in place on
/// `metadata.version_vector`.
///
/// Monotonic ([`VectorClock::observe`] = per-peer max), so a re-stamp
/// never regresses an entry. A no-op when `node_id` is empty or
/// `metadata` is not a JSON object. **Vector-clock discipline:** only a
/// LOCAL write advances this node's own component — the federation
/// *receive* write paths (`insert_if_newer` / `merge_inbound`) must NOT
/// call this; they learn other nodes' components solely via the
/// pointwise-max merge in [`merge_memory`].
pub fn stamp_version_vector(metadata: &mut Value, node_id: &str, at: &str) {
    if node_id.is_empty() {
        return;
    }
    let mut clock = parse_version_vector(metadata);
    clock.observe(node_id, at);
    if let (Some(obj), Ok(vc_value)) = (metadata.as_object_mut(), serde_json::to_value(&clock)) {
        obj.insert(field_names::VERSION_VECTOR.to_string(), vc_value);
    }
}

/// #1719 item 3a — trust rank of a row's stamped `metadata.attest_level`
/// for the attested-identity LWW tiebreak. A `claimed` / unsigned /
/// absent level is the floor (0); a verified `agent_attested` level
/// outranks it (1).
///
/// Reads the row's OWN stamped string. The federation merge boundary
/// (`merge_inbound`) calls [`sanitize_inbound_attestation`] on the
/// untrusted remote first, so a peer can NOT win this tiebreak by
/// self-asserting `agent_attested` — only the receiver's own stored
/// local level can win on attestation.
fn attest_rank(m: &Memory) -> u8 {
    let level = if m
        .metadata
        .get(field_names::ATTEST_LEVEL)
        .and_then(Value::as_str)
        == Some(AttestLevel::AgentAttested.as_str())
    {
        AttestLevel::AgentAttested
    } else {
        AttestLevel::Claimed
    };
    level.rank()
}

/// #1719 item 3a — neutralize an UNTRUSTED inbound row's self-asserted
/// `metadata.attest_level` to `claimed` before it is merged, so a peer
/// cannot win the attested-identity LWW tiebreak by self-asserting a
/// verified level. The local (receiver-stored) row keeps its own level.
///
/// Returns a sanitized clone; the key is only rewritten when it is
/// already present (so no `attest_level` key is introduced on a row that
/// never carried one — its rank is the `claimed` floor either way).
/// Applied identically by both adapters' `merge_inbound` so there is no
/// per-backend trust drift.
#[must_use]
pub fn sanitize_inbound_attestation(inbound: &Memory) -> Memory {
    let mut sanitized = inbound.clone();
    if let Some(obj) = sanitized.metadata.as_object_mut() {
        if obj.contains_key(field_names::ATTEST_LEVEL) {
            obj.insert(
                field_names::ATTEST_LEVEL.to_string(),
                Value::String(AttestLevel::Claimed.as_str().to_string()),
            );
        }
    }
    sanitized
}

/// #2863 — re-assert the RECEIVER-VERIFIED `agent_attested` level onto a merged
/// row when `receiver_verified` is set AND the merged row's `SignableWrite`
/// surface + `write_signature` is byte-identical to `verified_inbound` (the row
/// the federation receive path already verified against the origin author's
/// LOCALLY-ENROLLED key). [`sanitize_inbound_attestation`] correctly neutralizes
/// the inbound level for the LWW TIEBREAK — a peer must never win by
/// self-asserting `agent_attested` — but that must not DEMOTE a level THIS node
/// INDEPENDENTLY verified over the persisted bytes (env #94). Applied on the
/// merged row INSIDE the merge transaction and BEFORE the content-sealing write,
/// so the plaintext surface compare holds on at-rest-encrypted deployments too
/// (the `content` column becomes ciphertext only AFTER the write) and there is
/// no non-atomic crash window that could strand a TERMINAL tombstone at
/// `claimed`. `receiver_verified` is the caller's trust signal
/// (`row_is_agent_attested` of the row AFTER `apply_inbound_write_attestation`,
/// which always overwrites `attest_level` with THIS node's verdict); every
/// NON-receive caller passes `false` for a byte-identical legacy merge.
#[must_use]
pub fn reassert_verified_attestation(
    mut merged: Memory,
    verified_inbound: &Memory,
    receiver_verified: bool,
) -> Memory {
    if receiver_verified && signed_surface_matches(&merged, verified_inbound) {
        if let Some(obj) = merged.metadata.as_object_mut() {
            obj.insert(
                field_names::ATTEST_LEVEL.to_string(),
                Value::String(AttestLevel::AgentAttested.as_str().to_string()),
            );
        }
    }
    merged
}

/// #2863 — do two rows carry a byte-identical 6-field `SignableWrite` surface
/// (`agent_id` + `namespace` + `title` + `memory_kind` + `created_at` +
/// `content`) AND the same non-empty `write_signature`? The signature commits to
/// `sha256(content)` + the other five fields, so an identical signature over an
/// identical surface proves the persisted merged row IS the exact coherent
/// signed unit the receiver verified — never a field-wise CRDT accretion
/// (a "Frankenstein" row) nor a distinct signed unit. A missing/empty signature
/// or agent_id on either side is a non-match (fail-closed).
fn signed_surface_matches(a: &Memory, b: &Memory) -> bool {
    fn meta_str<'m>(m: &'m Memory, key: &str) -> Option<&'m str> {
        m.metadata.get(key).and_then(Value::as_str)
    }
    // `created_at` compared by INSTANT, not bytes: a lossless RFC3339
    // re-rendering (e.g. postgres round-tripping `TIMESTAMPTZ` back to the wire,
    // or `Z` vs `+00:00`) represents the SAME signed instant and must still
    // match, while a genuinely different `created_at` (a Frankenstein whose
    // timestamp came from a distinct row) is rejected — so the two backends
    // cannot drift on the rendering seam. Unparseable values fall back to byte
    // equality (fail-closed on the pathological case).
    let created_at_eq = match (
        chrono::DateTime::parse_from_rfc3339(&a.created_at),
        chrono::DateTime::parse_from_rfc3339(&b.created_at),
    ) {
        (Ok(x), Ok(y)) => x == y,
        _ => a.created_at == b.created_at,
    };
    let sig_a = meta_str(a, field_names::WRITE_SIGNATURE);
    let agent_a = meta_str(a, param_names::AGENT_ID);
    a.content == b.content
        && a.title == b.title
        && a.namespace == b.namespace
        && created_at_eq
        && a.memory_kind == b.memory_kind
        && agent_a == meta_str(b, param_names::AGENT_ID)
        && agent_a.is_some_and(|s| !s.is_empty())
        && sig_a == meta_str(b, field_names::WRITE_SIGNATURE)
        && sig_a.is_some_and(|s| !s.is_empty())
}

/// #1755 item 3b — cap an UNTRUSTED inbound row's `updated_at` to a
/// freshness ceiling (`now + skew_secs`) before it is merged, so a
/// federated relay cannot post-date `updated_at` — the PRIMARY LWW
/// tiebreak key — far into the future to clobber genuinely-newer local
/// rows. The signed envelope can't bind `updated_at` (it is system-mutated
/// after signing and not client-known at sign time), so a receive-boundary
/// freshness clamp — mirroring the `created_at` ±`ATTEST_CREATED_AT_SKEW_SECS`
/// window and the [`sanitize_inbound_attestation`] hook — is the
/// proportionate defense. Honest clock-skew (a few seconds) is untouched;
/// only an absurdly-future `updated_at` is clamped, bounding the relay's
/// post-dating reach from unbounded to `skew_secs`.
///
/// Takes the already-sanitized inbound by value (one clone for the whole
/// receive-boundary preparation). A malformed `now` / `updated_at` is a
/// no-op — never break the merge on a parse error.
#[must_use]
pub fn clamp_inbound_updated_at(mut inbound: Memory, now_rfc3339: &str, skew_secs: i64) -> Memory {
    if let (Ok(now), Ok(updated)) = (
        chrono::DateTime::parse_from_rfc3339(now_rfc3339),
        chrono::DateTime::parse_from_rfc3339(&inbound.updated_at),
    ) {
        let ceiling = now + chrono::Duration::seconds(skew_secs);
        if updated > ceiling {
            // Wave-2 B14: rewrite ONLY a real far-future postdate.
            // Honest inbound `updated_at` is preserved BYTE-VERBATIM
            // (round-trip invariant). Z vs `+00:00` LWW is the
            // comparison key [`lww_updated_at_key`], not this clamp.
            inbound.updated_at =
                crate::validate::render_canonical_utc(ceiling.with_timezone(&chrono::Utc));
        }
    }
    inbound
}

/// Delegate a #224 max-merged counter field to the [`PnCounter`] lattice
/// (monotonic — a merge never rolls the value backwards). Used for
/// `priority` / `confidence` / `access_count` / `version` /
/// `reflection_depth`.
fn merge_counter<T: PartialOrd + Clone>(local: T, remote: T) -> T {
    PnCounter::new(local)
        .merge(&PnCounter::new(remote))
        .into_inner()
}

/// Total-order LWW verdict: `true` when `remote` should win the
/// last-write-wins tiebreak over `local`.
///
/// The order is `(updated_at, attest_rank, id)` (#1719 item 3a): a
/// strictly-greater `updated_at` wins; on an `updated_at` tie the
/// higher attestation rank wins ([`attest_rank`] — a verified
/// `agent_attested` row beats an unsigned `claimed` one); and only on a
/// further tie does the lexically-greater `id` break it. Using a total
/// order over BOTH operands (rather than "remote wins only on
/// strict-greater, else keep local") is what makes [`merge_memory`]
/// fully commutative — `merge(a, b)` and `merge(b, a)` pick the same
/// side because the winner is a property of the pair, not of argument
/// position. Inserting `attest_rank` as the middle key keeps that
/// property (it is a deterministic function of each operand) while
/// preventing a same-`updated_at` unsigned edit from clobbering a
/// locally-attested row by `id` manipulation.
fn lww_updated_at_key(m: &Memory) -> Option<chrono::DateTime<chrono::Utc>> {
    // #4030 — the SAME instant order the merged `updated_at` is chosen by
    // ([`super::crdt_field_clock::later`]), so the content winner and the
    // stamped clock can never disagree.
    super::crdt_field_clock::instant_of(&m.updated_at)
}

fn remote_wins_lww(local: &Memory, remote: &Memory) -> bool {
    (
        lww_updated_at_key(remote),
        attest_rank(remote),
        remote.id.as_str(),
    ) > (
        lww_updated_at_key(local),
        attest_rank(local),
        local.id.as_str(),
    )
}

/// LWW pick of a cloneable field: returns `remote`'s value when it wins
/// the `(updated_at, attest_rank, id)` tiebreak, else `local`'s.
fn lww<T: Clone>(local: &Memory, remote: &Memory, local_val: &T, remote_val: &T) -> T {
    if remote_wins_lww(local, remote) {
        remote_val.clone()
    } else {
        local_val.clone()
    }
}

/// `tags` union with a deterministic, stable order: preserve `local`'s
/// order first, then append the `remote` tags not already seen. Dedup
/// is exact-string. The result is independent of argument order *as a
/// set* (the merge is commutative on tag membership); the surface
/// ordering is local-first by design and is asserted as a set in the
/// commutativity test.
///
/// #4032 — the union is BOUNDED by the replicated-state tag cap
/// ([`crate::validate::MAX_REPLICATED_TAGS`], the cap every full-row
/// receiver validates against), so a joined row can always be relayed.
/// Past the cap the join keeps the cap-many lexicographically SMALLEST tags:
/// "the k smallest of a union" is itself a join (commutative, associative,
/// idempotent), so replicas still converge; the drop is WARNed loudly and
/// the pre-merge row stays in the `federation_merge` archive snapshot.
fn merge_tags(local: &[String], remote: &[String]) -> Vec<String> {
    let mut union = OrSet::new(local.to_vec())
        .merge(&OrSet::new(remote.to_vec()))
        .into_inner();
    let cap = crate::validate::MAX_REPLICATED_TAGS;
    if union.len() > cap {
        let joined = union.len();
        union.sort();
        union.truncate(cap);
        tracing::warn!(
            target: CRDT_BOUND_TRACE_TARGET,
            joined,
            cap,
            "crdt merge: tag union exceeds the replicated-state cap; keeping the {cap} \
             lexicographically smallest tags (#4032 bounded join)"
        );
    }
    union
}

/// `tier` resolution (#224): **max durability** on the total order
/// `short < mid < long` — a merge NEVER downgrades a memory's
/// durability tier. `Tier` deliberately does not derive `Ord` (the
/// enum-proliferation audit #970 keeps the wire enums non-comparable),
/// so the durability rank is matched explicitly here. Commutative +
/// idempotent (it is a `max` over a 3-element chain).
fn merge_tier(local: &super::memory::Tier, remote: &super::memory::Tier) -> super::memory::Tier {
    use super::memory::Tier;
    // Durability rank: Short=0, Mid=1, Long=2. Take the higher.
    fn rank(t: &Tier) -> u8 {
        match t {
            Tier::Short => 0,
            Tier::Mid => 1,
            Tier::Long => 2,
        }
    }
    if rank(remote) > rank(local) {
        remote.clone()
    } else {
        local.clone()
    }
}

/// `expires_at` resolution (#224): **null = never expires, so null WINS
/// over any non-null** (preservation over loss); when both are present,
/// the later expiry wins — by INSTANT (#4030: a raw-string compare
/// mis-orders offset renderings), keeping the winner's original bytes.
fn merge_expires_at(local: &Option<String>, remote: &Option<String>) -> Option<String> {
    match (local, remote) {
        // Either side immortal ⇒ result immortal (null wins).
        (None, _) | (_, None) => None,
        (Some(l), Some(r)) => Some(super::crdt_field_clock::later(l, r).to_string()),
    }
}

/// Pre-#4031 whole-value fallback for a MALFORMED (non-object) metadata
/// operand: the row-level LWW winner's value is taken whole. The substrate's
/// `metadata` is always an object (`{}` by default, and the validator refuses
/// anything else), so this arm exists only so a corrupt row still merges.
fn lww_whole_value(local: &Value, remote: &Value, remote_wins: bool) -> Value {
    if remote_wins {
        remote.clone()
    } else {
        local.clone()
    }
}

/// Top-level metadata keys NOT resolved by the generic per-key LWW-element
/// map: each has its own rule, applied below (the node-local keys are added
/// from [`NODE_LOCAL_METADATA_KEYS`]).
const SPECIAL_METADATA_KEYS: [&str; 4] = [
    param_names::AGENT_ID,
    field_names::GOVERNANCE,
    field_names::VERSION_VECTOR,
    field_names::CRDT_FIELD_CLOCKS,
];

/// The metadata keys the visibility gate reads (`crate::visibility`): the
/// scope arm and the private arm's inbox-target / legacy-recipient grants.
/// The #4032 bounded fallback still resolves them through the full per-path
/// join, so a bounded merge never widens who can read a row.
const VISIBILITY_METADATA_KEYS: [&str; 3] = [
    crate::META_KEY_SCOPE,
    crate::META_KEY_TARGET_AGENT_ID,
    crate::META_KEY_RECIPIENT_AGENT_ID,
];

/// Resolve `metadata` (#224 + #4031).
///
/// Every ordinary key — at any depth — is an LWW-element-map entry resolved
/// by its OWN version ([`super::crdt_field_clock`]): a key present on one
/// side survives with the clock it was written at (never the merged row's
/// newer clock), a collision takes the newer version, objects merge
/// key-wise. `scope` is such an ordinary key (LWW, a conscious visibility
/// edit). Then the special keys: `agent_id` immutable→local, `governance`
/// →local, `version_vector` pointwise-max, the node-local keys →local, and
/// the rebuilt [`field_names::CRDT_FIELD_CLOCKS`] map.
fn merge_metadata(
    local: &Memory,
    remote: &Memory,
    clocks: &mut FieldClockMerge,
    bounded: bool,
) -> Value {
    let (Value::Object(lmap), Value::Object(rmap)) = (&local.metadata, &remote.metadata) else {
        return lww_whole_value(
            &local.metadata,
            &remote.metadata,
            remote_wins_lww(local, remote),
        );
    };
    let skip: Vec<&str> = SPECIAL_METADATA_KEYS
        .iter()
        .copied()
        .chain(NODE_LOCAL_METADATA_KEYS)
        .collect();
    // #4032 bounded fallback: the row-LWW loser contributes no ordinary key —
    // EXCEPT the authorization-bearing visibility keys, which always resolve
    // through the full per-path join so the bounded fallback can never make a
    // row visible to anyone the unbounded join would not (a retained older
    // `scope=collective` on the winner must still lose to the loser's newer
    // `scope=private`).
    let loser_visibility = |m: &Map<String, Value>| -> Map<String, Value> {
        VISIBILITY_METADATA_KEYS
            .iter()
            .filter_map(|k| m.get(*k).map(|v| ((*k).to_string(), v.clone())))
            .collect()
    };
    let (l_bounded, r_bounded);
    let (lgen, rgen) = match (bounded, remote_wins_lww(local, remote)) {
        (false, _) => (lmap, rmap),
        (true, true) => {
            l_bounded = loser_visibility(lmap);
            (&l_bounded, rmap)
        }
        (true, false) => {
            r_bounded = loser_visibility(rmap);
            (lmap, &r_bounded)
        }
    };
    let mut map = clocks.merge_metadata_keys(lgen, rgen, &skip, &VISIBILITY_METADATA_KEYS);

    // agent_id — immutable, original (local) wins. Write-once NHI
    // provenance (Task 1.8 #196): a peer must never rewrite it. Local never
    // had one ⇒ absent (a remote-introduced agent_id is NOT provenance the
    // local row authored; absence is the original).
    if let Some(local_agent) = lmap.get(param_names::AGENT_ID) {
        map.insert(param_names::AGENT_ID.to_string(), local_agent.clone());
    }

    // governance — keep local's (owner-only override; a merge must not let
    // a peer rewrite governance).
    if let Some(local_gov) = lmap.get(field_names::GOVERNANCE) {
        map.insert(field_names::GOVERNANCE.to_string(), local_gov.clone());
    }

    // version_vector — per-memory CRDT vector clock (#1756 / #1719 item 2).
    // MUST merge by pointwise-max (`VectorClock::merge`): a per-peer
    // timestamp collision resolved by any LWW would DISCARD a peer
    // observation the losing row carried (the 5-agent vote 4d3ea1c5
    // finding). Carried + merged only (ship-but-don't-gate, #1709 /
    // 0623aebf). Absent on both sides ⇒ key stays absent.
    let mut merged_vc = parse_version_vector(&local.metadata);
    merged_vc.merge(&parse_version_vector(&remote.metadata));
    if !merged_vc.entries.is_empty()
        && let Ok(vc_value) = serde_json::to_value(&merged_vc)
    {
        map.insert(field_names::VERSION_VECTOR.to_string(), vc_value);
    }

    // v0.9.0 G7 (#1824) — the three `contradiction_*` markers are node-local:
    // they encode a LOCAL conserve decision + soft down-weight and MUST NOT
    // leak to — or arrive from — a peer, or a peer's re-entry gate in
    // `autonomy::forget_if_superseded` would trip on a marker it never
    // authored. LOCAL wins: keep local's value, drop any remote-introduced
    // key. Boids item 3 R2.3 (#3266) — the #3324 `contamination` marker is
    // node-local by the SAME rule.
    for key in NODE_LOCAL_METADATA_KEYS {
        if let Some(local_val) = lmap.get(key) {
            map.insert(key.to_string(), local_val.clone());
        }
    }

    Value::Object(map)
}

/// Tracing target of the #4032 bounded-join WARNs (tags / metadata past the
/// replicated-state caps).
pub const CRDT_BOUND_TRACE_TARGET: &str = "crdt.bounded_join";

/// The fields [`merge_memory`] resolves through the #4031 per-field clocks.
struct ClockedFields {
    metadata: Value,
    valid_until: Option<String>,
    entity_id: Option<String>,
    persona_version: Option<i32>,
    citations: Vec<super::memory::Citation>,
    source_uri: Option<String>,
    source_span: Option<super::memory::SourceSpan>,
    confidence_signals: Option<super::memory::ConfidenceSignals>,
    confidence_decayed_at: Option<String>,
}

/// #4032 — does a joined `metadata` exceed the replicated-state size cap
/// (the bound every full-row receiver validates against)?
fn metadata_exceeds_replicated_cap(metadata: &Value) -> bool {
    // An unserializable value counts as over the cap (take the bounded
    // fallback rather than persist something unmeasurable).
    !serde_json::to_string(metadata)
        .is_ok_and(|s| s.len() <= crate::validate::MAX_REPLICATED_METADATA_SIZE)
}

/// Resolve `metadata` and the optional provenance fields through ONE
/// [`FieldClockMerge`] (#4031). `bounded` (#4032) drops the row-LWW LOSER's
/// ordinary metadata keys — the deterministic fallback when the full join
/// would exceed the replicated cap.
fn resolve_clocked_fields(local: &Memory, remote: &Memory, bounded: bool) -> ClockedFields {
    let mut clocks = FieldClockMerge::new(
        &local.metadata,
        &local.updated_at,
        attest_rank(local),
        &remote.metadata,
        &remote.updated_at,
        attest_rank(remote),
    );
    let mut metadata = merge_metadata(local, remote, &mut clocks, bounded);
    let valid_until = clocks.merge_opt(
        field_names::VALID_UNTIL,
        &local.valid_until,
        &remote.valid_until,
    );
    let entity_id = clocks.merge_opt(field_names::ENTITY_ID, &local.entity_id, &remote.entity_id);
    let persona_version = clocks.merge_opt(
        field_names::PERSONA_VERSION,
        &local.persona_version,
        &remote.persona_version,
    );
    // An empty `citations` vec is "absent" (a peer carrying fact-provenance
    // is not clobbered by a row that recorded none).
    let non_empty = |c: &Vec<super::memory::Citation>| (!c.is_empty()).then(|| c.clone());
    let citations = clocks
        .merge_opt(
            param_names::CITATIONS,
            &non_empty(&local.citations),
            &non_empty(&remote.citations),
        )
        .unwrap_or_default();
    let source_uri = clocks.merge_opt(
        field_names::SOURCE_URI,
        &local.source_uri,
        &remote.source_uri,
    );
    let source_span = clocks.merge_opt(
        field_names::SOURCE_SPAN,
        &local.source_span,
        &remote.source_span,
    );
    let confidence_signals = clocks.merge_opt(
        field_names::CONFIDENCE_SIGNALS,
        &local.confidence_signals,
        &remote.confidence_signals,
    );
    let confidence_decayed_at = clocks.merge_opt(
        field_names::CONFIDENCE_DECAYED_AT,
        &local.confidence_decayed_at,
        &remote.confidence_decayed_at,
    );
    if let (Some(clock_map), Value::Object(map)) = (clocks.finish(), &mut metadata) {
        map.insert(field_names::CRDT_FIELD_CLOCKS.to_string(), clock_map);
    }
    ClockedFields {
        metadata,
        valid_until,
        entity_id,
        persona_version,
        citations,
        source_uri,
        source_span,
        confidence_signals,
        confidence_decayed_at,
    }
}

/// v0.8.0 Pillar-3 (#1709 / #224) — pure, deterministic CRDT-lite merge
/// of two divergent same-`id` [`Memory`] rows.
///
/// Resolves every field per the canonical #224 design table (see the
/// module docs). **Precondition:** `local.id == remote.id` (same row);
/// `debug_assert_eq!`-checked. The returned [`Memory`] is constructed
/// field-by-field with NO `..local.clone()` rest-spread, so a future
/// field added to [`Memory`] fails to compile here until an explicit
/// merge rule is chosen for it.
///
/// Pure: no I/O, no clock reads. Commutative + associative (up to the
/// `(updated_at, id)` LWW total order) + idempotent — except past the #4032
/// metadata byte cap, where the bounded fallback is commutative (for distinct
/// `(updated_at, attest_rank)`) but not associative (see the module docs).
#[must_use]
pub fn merge_memory(local: &Memory, remote: &Memory) -> Memory {
    debug_assert_eq!(
        local.id, remote.id,
        "merge_memory precondition: both operands must carry the same id"
    );

    // #4031 — per-field clocks: every retained metadata value and optional
    // field keeps the version it was written at, never the merged row's.
    // #4032 — the joined metadata is bounded by the REPLICATED-state cap the
    // receivers validate against; past it the join degrades deterministically
    // to the row-LWW winner's metadata (commutative for distinct clocks, never
    // unrelayable; see the module docs for the equal-clock residual).
    let mut clocked = resolve_clocked_fields(local, remote, false);
    if metadata_exceeds_replicated_cap(&clocked.metadata) {
        tracing::warn!(
            target: CRDT_BOUND_TRACE_TARGET,
            memory_id = %local.id,
            cap = crate::validate::MAX_REPLICATED_METADATA_SIZE,
            "crdt merge: joined metadata exceeds the replicated-state cap; keeping the \
             row-LWW winner's metadata (the loser's disjoint keys stay in the \
             pre-merge archive snapshot) (#4032 bounded join)"
        );
        clocked = resolve_clocked_fields(local, remote, true);
    }
    let ClockedFields {
        metadata,
        valid_until,
        entity_id,
        persona_version,
        citations,
        source_uri,
        source_span,
        confidence_signals,
        confidence_decayed_at,
    } = clocked;

    Memory {
        // `id` — equality (precondition above). Both args share it; take
        // local's deterministically.
        id: local.id.clone(),
        // v0.9.0 G8 (#1825) — `cid` is genesis identity, immutable and
        // never LWW'd: a federation merge PRESERVES the LOCAL row's
        // content-id (the persist path `overwrite_full_row_by_id` leaves
        // `cid`/`cid_genesis` untouched, so this carried value is
        // informational). `federation_merge_preserves_local_cid`.
        cid: local.cid.clone(),
        // #1834 claim-bitemporal VALID-time (#2207 fix): `valid_from` is the
        // genesis assertion instant — LOCAL-wins (immutable), matching the
        // `(title, namespace)` upsert arms' `valid_from = memories.valid_from`
        // rule and the fact that no UPDATE SET list ever rewrites it.
        // `valid_until` is caller-CLOSABLE, so it MUST resolve NEWER-WINS by
        // the same `(updated_at, attest_rank, id)` LWW tiebreak the rest of the
        // row uses — otherwise a peer that CLOSED a claim (newer `updated_at`,
        // `valid_until = Some(T)`) would merge to the local OPEN value (`None`)
        // and replicas would DIVERGE on VALID-time (a `valid_at` recall on the
        // receiver would keep returning the closed claim as still-asserted).
        // Present beats absent, so a close is sticky against a stale remote
        // reopen-to-`None`; #4031 — with the close's OWN clock.
        valid_from: local.valid_from.clone(),
        valid_until,
        // `tier` — max durability (short < mid < long); never downgrade.
        tier: merge_tier(&local.tier, &remote.tier),
        // `namespace` — LWW by updated_at (tiebreak id).
        namespace: lww(local, remote, &local.namespace, &remote.namespace),
        // `title` — LWW by updated_at.
        title: lww(local, remote, &local.title, &remote.title),
        // `content` — LWW by updated_at.
        content: lww(local, remote, &local.content, &remote.content),
        // `tags` — union (dedup, stable local-first order).
        tags: merge_tags(&local.tags, &remote.tags),
        // `priority` — max (PN-Counter).
        priority: merge_counter(local.priority, remote.priority),
        // `confidence` — max (PN-Counter).
        confidence: merge_counter(local.confidence, remote.confidence),
        // `source` — LWW by updated_at.
        source: lww(local, remote, &local.source, &remote.source),
        // `access_count` — max (PN-Counter).
        access_count: merge_counter(local.access_count, remote.access_count),
        // `created_at` — min (earliest creation), by INSTANT (#4030); the
        // winner keeps its original (signed) bytes.
        created_at: super::crdt_field_clock::earlier(&local.created_at, &remote.created_at)
            .to_string(),
        // `updated_at` — max (latest update), by the SAME instant order the
        // content LWW uses (#4030): the merged row's clock can never regress
        // below the content it carries.
        updated_at: super::crdt_field_clock::later(&local.updated_at, &remote.updated_at)
            .to_string(),
        // `last_accessed_at` — max; absence is the floor, so a present
        // value beats None (prefer-non-null), and on both-present the
        // later stamp wins.
        last_accessed_at: max_opt_string(&local.last_accessed_at, &remote.last_accessed_at),
        // `expires_at` — max, BUT null (never-expires) wins over any
        // non-null (preservation over loss).
        expires_at: merge_expires_at(&local.expires_at, &remote.expires_at),
        // `metadata` — per-key LWW-element map + the special keys (#4031).
        metadata,
        // `reflection_depth` — max (PN-Counter; monotonic — the
        // reflection signal must not be lost on merge).
        reflection_depth: merge_counter(local.reflection_depth, remote.reflection_depth),
        // #224: memory_kind not in design table — LWW per table
        // philosophy (a conscious typing choice, like title).
        memory_kind: lww(local, remote, &local.memory_kind, &remote.memory_kind),
        // #224 structural / provenance fields (entity_id, persona_version,
        // citations, source_uri, source_span): prefer non-null, else the
        // newer value — #4031 each by its OWN clock (resolved above).
        entity_id,
        persona_version,
        citations,
        source_uri,
        source_span,
        // #224: confidence_source not in design table — LWW per table
        // philosophy (follows the confidence write).
        confidence_source: lww(
            local,
            remote,
            &local.confidence_source,
            &remote.confidence_source,
        ),
        // #224: confidence_signals / confidence_decayed_at — prefer
        // non-null, else the newer value by its own clock (#4031).
        confidence_signals,
        confidence_decayed_at,
        // #224: version not in design table — max (PN-Counter; monotonic
        // optimistic-concurrency counter; never roll backwards).
        version: merge_counter(local.version, remote.version),
        // Boids item 3 R2.1 (#3266 / #3750 / #3905, vote `4d3ea1c5`, ruling
        // variant B): LWW for ordinary states (tombstoned included), but a
        // LOCAL contaminated / quarantined overlay is never replaced and a
        // remote taint is never adopted. See `merge_lifecycle_local_taint_wins`.
        lifecycle_state: merge_lifecycle_local_taint_wins(local, remote),
    }
}

/// Boids item 3 R2 (#3266, ruling tmux-22 variant B) — the node-local
/// containment overlay states: the #3324 taint and the #1948 route-IN
/// quarantine. `tombstoned` is deliberately NOT here: a lifecycle tombstone is
/// a REPLICATED deletion that must converge fleet-wide (the title-slot
/// supersede lane, pinned by `federation_causal_order_3699`), so it keeps its
/// newer-wins adoption. One source for the Rust predicate, the SQL twin and
/// the receive-gate normalisation.
pub const NODE_LOCAL_LIFECYCLE_STATES: [LifecycleState; 2] =
    [LifecycleState::Contaminated, LifecycleState::Quarantined];

/// Whether `state` is a node-local containment overlay
/// ([`NODE_LOCAL_LIFECYCLE_STATES`]).
#[must_use]
pub fn is_node_local_lifecycle(state: LifecycleState) -> bool {
    NODE_LOCAL_LIFECYCLE_STATES.contains(&state)
}

/// Boids item 3 R2.1 (#3266; fixes #3750) — the ONE lifecycle merge
/// predicate.
///
/// * A LOCAL `contaminated` / `quarantined` state (a node-local overlay) is
///   never replaced by the remote, whatever the timestamps say — the
///   LOCAL-wins precedent of the node-local `contradiction_*` keys and
///   `governance`. Reversal is a deliberate, signed act (the operator
///   decontaminate / dequarantine route-OUT, R2.5), never a peer write.
/// * A REMOTE `contaminated` is never adopted (only this node's own stamp or
///   rewind may taint a row; the per-write signature does not cover
///   `lifecycle_state`, so a wire taint is unattested).
/// * A REMOTE `quarantined` takes the ordinary newer-wins pick. Every inbound
///   federation funnel normalises a WIRE overlay to `open`
///   ([`normalise_inbound_node_local_overlay`], R2.3) BEFORE the #1948
///   route-IN verdict, so a `quarantined` that reaches the merge is THIS
///   node's own route-IN decision — keying the refusal on it would silently
///   disable #1948 over an existing row (spec R2.3: key on the LOCAL state).
/// * Everything else — including `tombstoned` — is the #224 last-writer-wins.
///
/// Deliberately NOT commutative when a side is a node-local overlay.
#[must_use]
pub fn merge_lifecycle_local_taint_wins(local: &Memory, remote: &Memory) -> LifecycleState {
    if is_node_local_lifecycle(local.lifecycle_state)
        || remote.lifecycle_state == LifecycleState::Contaminated
    {
        return local.lifecycle_state;
    }
    lww(
        local,
        remote,
        &local.lifecycle_state,
        &remote.lifecycle_state,
    )
}

/// The SQL twin of [`merge_lifecycle_local_taint_wins`] for the upsert
/// `ON CONFLICT` arms of BOTH backends (`new` = the incoming row alias,
/// `old` = the stored row alias), so sqlite and postgres cannot drift. The
/// state lists are built from [`NODE_LOCAL_LIFECYCLE_STATES`] (one source).
#[must_use]
pub fn lifecycle_local_taint_wins_case(new: &str, old: &str) -> String {
    let local_wins = NODE_LOCAL_LIFECYCLE_STATES
        .map(|s| format!("'{}'", s.as_str()))
        .join(", ");
    let contaminated = LifecycleState::Contaminated.as_str();
    format!(
        "CASE WHEN {old}.lifecycle_state IN ({local_wins}) \
              OR {new}.lifecycle_state = '{contaminated}' \
         THEN {old}.lifecycle_state \
         WHEN {new}.updated_at > {old}.updated_at \
              OR ({new}.updated_at = {old}.updated_at AND {new}.id > {old}.id) \
         THEN {new}.lifecycle_state ELSE {old}.lifecycle_state END"
    )
}

/// The node-local metadata keys (#1824 G7 `contradiction_*` + the #3324
/// `contamination` marker): a LOCAL value survives every federation merge and
/// a peer's is never adopted — in [`merge_memory`] and in the title-slot
/// newer-wins SQL arm of BOTH adapters (f1 goal4 FB). One source.
pub const NODE_LOCAL_METADATA_KEYS: [&str; 4] = [
    field_names::CONTRADICTION_CONSERVED,
    field_names::CONTRADICTION_SOFT_LOSER,
    field_names::CONTRADICTION_WINNER_ID,
    crate::storage::CONTAMINATION_METADATA_KEY,
];

fn node_local_keys_sql() -> String {
    NODE_LOCAL_METADATA_KEYS
        .map(|k| format!("'{k}'"))
        .join(", ")
}

/// SQLite title-slot newer-wins metadata base (f1 goal4 FB): the incoming
/// row's metadata with every node-local key removed, then the LOCAL row's
/// node-local keys patched back on. `excluded` / `memories` are the upsert
/// aliases.
#[must_use]
pub fn sqlite_title_slot_newer_metadata() -> String {
    let paths = NODE_LOCAL_METADATA_KEYS
        .map(|k| format!("'$.{k}'"))
        .join(", ");
    // `json_each.value` is an SQL value: a JSON boolean surfaces as 0/1 and a
    // string loses its quotes, so each value is re-typed through `json(...)`
    // from its `type` — the G7 soft-loser marker stays the JSON boolean the
    // writer stamped (the postgres predicate matches `'true'`).
    format!(
        "json_patch(json_remove(excluded.metadata, {paths}), COALESCE((SELECT \
         json_group_object(key, json(CASE type WHEN 'true' THEN 'true' WHEN 'false' THEN 'false' \
         WHEN 'object' THEN value WHEN 'array' THEN value ELSE json_quote(value) END)) \
         FROM json_each(memories.metadata) WHERE key IN ({})), '{{}}'))",
        node_local_keys_sql()
    )
}

/// The postgres twin of [`sqlite_title_slot_newer_metadata`] (`EXCLUDED` /
/// `memories` aliases, `jsonb`).
#[must_use]
pub fn pg_title_slot_newer_metadata() -> String {
    pg_node_local_overlay("EXCLUDED.metadata")
}

/// `incoming` (a `jsonb` expression) with every node-local key removed, then
/// the node-local keys of the row being UPDATED (`memories.metadata`, read in
/// the same statement) overlaid — an atomic jsonb merge, so a writer never
/// writes back a node-local value from a copy it read earlier (f1 goal4 FA/FB).
#[must_use]
pub fn pg_node_local_overlay(incoming: &str) -> String {
    let keys = node_local_keys_sql();
    format!(
        "(({incoming} - ARRAY[{keys}]::text[]) || COALESCE((SELECT \
         jsonb_object_agg(nl.k, nl.v) FROM jsonb_each(CASE WHEN jsonb_typeof(memories.metadata) \
         = 'object' THEN memories.metadata ELSE '{{}}'::jsonb END) AS nl(k, v) WHERE nl.k IN ({keys})), \
         '{{}}'::jsonb))"
    )
}

/// Boids item 3 R2.3 (#3266) — the receive-gate normalisation of an INBOUND
/// row, applied by every federation funnel (push, both backends, and the pull
/// lanes via `sanitize_inbound_pull_memory`) BEFORE the #1948 route-IN
/// quarantine verdict:
///
/// * a wire `contaminated` / `quarantined` lifecycle becomes `open` — a fresh
///   row lands `open`, and over an existing row the LOCAL-wins merge applies;
/// * a wire `metadata.contamination` marker is removed — never adopted, the
///   same rule as the node-local `contradiction_*` keys.
///
/// Neither field is inside the per-write signed surface (`SignableWrite`
/// commits agent / namespace / title / kind / created_at / content hash), so
/// this never invalidates a presented `write_signature`. Returns `true` when
/// the row was changed.
pub fn normalise_inbound_node_local_overlay(mem: &mut Memory) -> bool {
    let mut changed = false;
    if is_node_local_lifecycle(mem.lifecycle_state) {
        mem.lifecycle_state = LifecycleState::Open;
        changed = true;
    }
    if let Some(obj) = mem.metadata.as_object_mut() {
        changed |= obj
            .remove(crate::storage::CONTAMINATION_METADATA_KEY)
            .is_some();
    }
    changed
}

/// `max` of two RFC3339-string `Option`s with absence as the floor: a
/// present value beats `None`, and on both-present the lexically-greater
/// (later) stamp wins. Used for `last_accessed_at`.
fn max_opt_string(local: &Option<String>, remote: &Option<String>) -> Option<String> {
    match (local, remote) {
        // #4030 — by instant, not bytes.
        (Some(l), Some(r)) => Some(super::crdt_field_clock::later(l, r).to_string()),
        (Some(l), None) => Some(l.clone()),
        (None, Some(r)) => Some(r.clone()),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::memory::{ConfidenceSource, LifecycleState, MemoryKind, SourceSpan, Tier};
    use serde_json::json;

    /// A baseline row. `updated_at` / `id` are set so callers can shape
    /// the LWW order deterministically.
    fn base(id: &str, updated_at: &str) -> Memory {
        Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: id.to_string(),
            tier: Tier::Short,
            namespace: "ns".to_string(),
            title: "t".to_string(),
            content: "c".to_string(),
            tags: vec![],
            priority: 1,
            confidence: 0.1,
            source: "user".to_string(),
            access_count: 0,
            created_at: "2026-06-16T00:00:00+00:00".to_string(),
            updated_at: updated_at.to_string(),
            last_accessed_at: None,
            expires_at: None,
            metadata: json!({}),
            reflection_depth: 0,
            memory_kind: MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: vec![],
            source_uri: None,
            source_span: None,
            confidence_source: ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: LifecycleState::Open,
        }
    }

    /// Serialise to a JSON value for equality comparison (Memory has no
    /// PartialEq derive).
    fn as_json(m: &Memory) -> Value {
        serde_json::to_value(m).expect("Memory serialises")
    }

    /// #2207 — the #1834 claim-bitemporal `valid_until` MUST resolve so a
    /// peer that CLOSED a claim wins by id: a remote-newer close (present
    /// `valid_until`, newer `updated_at`) replaces the local OPEN value
    /// (`None`); a stale remote open (`None`, older `updated_at`) does NOT
    /// clobber a fresher local close; `valid_from` stays LOCAL-immutable.
    #[test]
    fn merge_memory_valid_until_close_wins_and_valid_from_local() {
        // (a) remote-newer close wins over local open.
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.valid_from = Some("2026-06-01T00:00:00+00:00".into());
        local.valid_until = None; // open
        let mut remote = base("a", "2026-06-16T09:00:00+00:00");
        remote.valid_from = Some("2026-06-02T00:00:00+00:00".into()); // must be ignored
        remote.valid_until = Some("2026-06-10T00:00:00+00:00".into()); // closed
        let merged = merge_memory(&local, &remote);
        assert_eq!(
            merged.valid_until.as_deref(),
            Some("2026-06-10T00:00:00+00:00"),
            "a peer's newer close must win (replicates by id)"
        );
        assert_eq!(
            merged.valid_from.as_deref(),
            Some("2026-06-01T00:00:00+00:00"),
            "valid_from is LOCAL-immutable (genesis-wins, like the upsert arm)"
        );

        // (b) a stale remote open must NOT reopen a fresher local close.
        let mut local_closed = base("a", "2026-06-16T09:00:00+00:00");
        local_closed.valid_until = Some("2026-06-10T00:00:00+00:00".into());
        let mut stale_open = base("a", "2026-06-16T00:00:00+00:00");
        stale_open.valid_until = None;
        let merged_b = merge_memory(&local_closed, &stale_open);
        assert_eq!(
            merged_b.valid_until.as_deref(),
            Some("2026-06-10T00:00:00+00:00"),
            "a stale open must not clobber a fresher local close (close is sticky)"
        );
    }

    #[test]
    fn merge_memory_tags_union_dedup_both_survive() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.tags = vec!["x".into(), "shared".into()];
        let mut remote = base("a", "2026-06-16T00:00:01+00:00");
        remote.tags = vec!["shared".into(), "y".into()];

        let merged = merge_memory(&local, &remote);
        // Both agents' tags survive; "shared" deduped once.
        assert_eq!(merged.tags, vec!["x", "shared", "y"]);
    }

    #[test]
    fn merge_memory_priority_max() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.priority = 3;
        let mut remote = base("a", "2026-06-16T00:00:01+00:00");
        remote.priority = 9;
        assert_eq!(merge_memory(&local, &remote).priority, 9);
        // Order-independent.
        assert_eq!(merge_memory(&remote, &local).priority, 9);
    }

    #[test]
    fn merge_memory_confidence_max() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.confidence = 0.2;
        let mut remote = base("a", "2026-06-16T00:00:01+00:00");
        remote.confidence = 0.8;
        assert!((merge_memory(&local, &remote).confidence - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn merge_memory_access_count_max() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.access_count = 40;
        let mut remote = base("a", "2026-06-16T00:00:01+00:00");
        remote.access_count = 7;
        assert_eq!(merge_memory(&local, &remote).access_count, 40);
    }

    #[test]
    fn merge_memory_created_at_min() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.created_at = "2026-06-16T05:00:00+00:00".into();
        let mut remote = base("a", "2026-06-16T00:00:01+00:00");
        remote.created_at = "2026-06-16T01:00:00+00:00".into();
        // Earliest creation wins.
        assert_eq!(
            merge_memory(&local, &remote).created_at,
            "2026-06-16T01:00:00+00:00"
        );
    }

    #[test]
    fn merge_memory_updated_at_max() {
        let local = base("a", "2026-06-16T00:00:00+00:00");
        let remote = base("a", "2026-06-16T09:00:00+00:00");
        assert_eq!(
            merge_memory(&local, &remote).updated_at,
            "2026-06-16T09:00:00+00:00"
        );
    }

    #[test]
    fn merge_memory_expires_at_null_wins_over_date() {
        // local has an expiry, remote is immortal (null) ⇒ null wins.
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.expires_at = Some("2026-06-17T00:00:00+00:00".into());
        let remote = base("a", "2026-06-16T00:00:01+00:00"); // expires_at None
        assert_eq!(merge_memory(&local, &remote).expires_at, None);
        // Commutative.
        assert_eq!(merge_memory(&remote, &local).expires_at, None);
    }

    #[test]
    fn merge_memory_expires_at_max_when_both_present() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.expires_at = Some("2026-06-17T00:00:00+00:00".into());
        let mut remote = base("a", "2026-06-16T00:00:01+00:00");
        remote.expires_at = Some("2026-06-20T00:00:00+00:00".into());
        // Later expiry wins.
        assert_eq!(
            merge_memory(&local, &remote).expires_at,
            Some("2026-06-20T00:00:00+00:00".into())
        );
    }

    #[test]
    fn merge_memory_tier_max_durability() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.tier = Tier::Mid;
        let mut remote = base("a", "2026-06-16T00:00:01+00:00");
        remote.tier = Tier::Long;
        assert_eq!(merge_memory(&local, &remote).tier, Tier::Long);
        // Never downgrade: long + short ⇒ long.
        let mut s = base("a", "2026-06-16T00:00:02+00:00");
        s.tier = Tier::Short;
        let mut l = base("a", "2026-06-16T00:00:00+00:00");
        l.tier = Tier::Long;
        assert_eq!(merge_memory(&s, &l).tier, Tier::Long);
    }

    #[test]
    fn merge_memory_lww_newer_updated_at_wins() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.title = "old".into();
        local.content = "old-c".into();
        local.namespace = "old-ns".into();
        local.memory_kind = MemoryKind::Observation;
        local.lifecycle_state = LifecycleState::Open;

        let mut remote = base("a", "2026-06-16T09:00:00+00:00");
        remote.title = "new".into();
        remote.content = "new-c".into();
        remote.namespace = "new-ns".into();
        remote.memory_kind = MemoryKind::Decision;
        remote.lifecycle_state = LifecycleState::Done;

        let merged = merge_memory(&local, &remote);
        assert_eq!(merged.title, "new");
        assert_eq!(merged.content, "new-c");
        assert_eq!(merged.namespace, "new-ns");
        assert_eq!(merged.memory_kind, MemoryKind::Decision);
        assert_eq!(merged.lifecycle_state, LifecycleState::Done);
    }

    #[test]
    fn merge_memory_local_taint_survives_and_remote_taint_is_not_adopted() {
        // Boids item 3 R2.4 (#3266 / #3750) — REWRITTEN from the pre-R2
        // `..._participates_in_lww` pin, which asserted the opposite: that a
        // newer remote visible state CLEARS a local taint (and a newer remote
        // taint is ADOPTED). Under R2.1 (variant B) containment is a
        // node-local overlay: a local contaminated / quarantined state is never
        // replaced by the wire, and a wire taint is never adopted. Reversal is
        // the signed operator decontaminate (R2.5), never a peer write.
        let mut older_contaminated = base("a", "2026-06-16T00:00:00+00:00");
        older_contaminated.lifecycle_state = LifecycleState::Contaminated;
        let mut newer_open = base("a", "2026-06-16T09:00:00+00:00");
        newer_open.lifecycle_state = LifecycleState::Open;
        // FLIPPED: the local taint survives a strictly-newer remote visible state.
        assert_eq!(
            merge_memory(&older_contaminated, &newer_open).lifecycle_state,
            LifecycleState::Contaminated
        );
        // A remote taint is NOT adopted over a local visible state (a
        // hand-crafted push cannot taint-DoS a node).
        assert_eq!(
            merge_memory(&newer_open, &older_contaminated).lifecycle_state,
            LifecycleState::Open
        );
        // A LOCAL quarantine (the #1948 overlay) also survives a newer remote.
        let mut local_q = base("a", "2026-06-16T00:00:00+00:00");
        local_q.lifecycle_state = LifecycleState::Quarantined;
        assert_eq!(
            merge_memory(&local_q, &newer_open).lifecycle_state,
            LifecycleState::Quarantined
        );
        // A remote taint is not adopted even when the local row is tombstoned.
        let mut local_t = base("a", "2026-06-16T00:00:00+00:00");
        local_t.lifecycle_state = LifecycleState::Tombstoned;
        let mut newer_c = base("a", "2026-06-16T09:00:00+00:00");
        newer_c.lifecycle_state = LifecycleState::Contaminated;
        assert_eq!(
            merge_memory(&local_t, &newer_c).lifecycle_state,
            LifecycleState::Tombstoned
        );
        // Ruling variant B: `tombstoned` is a REPLICATED deletion — it keeps
        // newer-wins in BOTH directions (the #3699 title-slot convergence).
        let mut newer_t = base("a", "2026-06-16T09:00:00+00:00");
        newer_t.lifecycle_state = LifecycleState::Tombstoned;
        let mut older_open2 = base("a", "2026-06-16T00:00:00+00:00");
        older_open2.lifecycle_state = LifecycleState::Open;
        assert_eq!(
            merge_memory(&older_open2, &newer_t).lifecycle_state,
            LifecycleState::Tombstoned
        );
        assert_eq!(
            merge_memory(&local_t, &newer_open).lifecycle_state,
            LifecycleState::Open
        );
        // A `quarantined` reaching the merge is THIS node's #1948 route-IN
        // verdict (the wire value was normalised to `open` first, R2.3), so it
        // takes the ordinary newer-wins pick over a visible local row.
        let mut newer_q = base("a", "2026-06-16T09:00:00+00:00");
        newer_q.lifecycle_state = LifecycleState::Quarantined;
        assert_eq!(
            merge_memory(&older_open2, &newer_q).lifecycle_state,
            LifecycleState::Quarantined
        );
        // SYMMETRY KEPT for non-taint states: ordinary LWW, both argument orders.
        let mut older_open = base("a", "2026-06-16T00:00:00+00:00");
        older_open.lifecycle_state = LifecycleState::Open;
        let mut newer_done = base("a", "2026-06-16T09:00:00+00:00");
        newer_done.lifecycle_state = LifecycleState::Done;
        assert_eq!(
            merge_memory(&older_open, &newer_done).lifecycle_state,
            LifecycleState::Done
        );
        assert_eq!(
            merge_memory(&newer_done, &older_open).lifecycle_state,
            LifecycleState::Done
        );
    }

    #[test]
    fn merge_memory_contamination_marker_is_node_local_3266() {
        // Boids item 3 R2.3 — the local marker (the restore anchor) survives a
        // newer remote clean row; a remote marker is never adopted.
        let key = crate::storage::CONTAMINATION_METADATA_KEY;
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.lifecycle_state = LifecycleState::Contaminated;
        local.metadata = json!({ key: { "prior_lifecycle_state": "done" } });
        let mut remote = base("a", "2026-06-16T09:00:00+00:00");
        remote.metadata = json!({ "note": "peer" });
        let merged = merge_memory(&local, &remote);
        assert_eq!(merged.metadata[key]["prior_lifecycle_state"], "done");
        assert_eq!(merged.metadata["note"], "peer");

        let clean_local = base("a", "2026-06-16T00:00:00+00:00");
        let mut marked_remote = base("a", "2026-06-16T09:00:00+00:00");
        marked_remote.metadata = json!({ key: { "prior_lifecycle_state": "open" } });
        assert!(
            merge_memory(&clean_local, &marked_remote)
                .metadata
                .get(key)
                .is_none(),
            "a remote contamination marker must never be adopted"
        );
    }

    #[test]
    fn normalise_inbound_node_local_overlay_3266() {
        // Boids item 3 R2.3 — the receive gate: a wire taint / quarantine lands
        // `open` with no marker; a wire tombstone and ordinary states pass
        // through untouched (variant B).
        let key = crate::storage::CONTAMINATION_METADATA_KEY;
        for st in NODE_LOCAL_LIFECYCLE_STATES {
            let mut m = base("a", "2026-06-16T00:00:00+00:00");
            m.lifecycle_state = st;
            m.metadata = json!({ key: { "prior_lifecycle_state": "done" }, "k": 1 });
            assert!(normalise_inbound_node_local_overlay(&mut m));
            assert_eq!(m.lifecycle_state, LifecycleState::Open);
            assert!(m.metadata.get(key).is_none());
            assert_eq!(m.metadata["k"], 1);
        }
        for st in [
            LifecycleState::Tombstoned,
            LifecycleState::Done,
            LifecycleState::Open,
        ] {
            let mut m = base("a", "2026-06-16T00:00:00+00:00");
            m.lifecycle_state = st;
            assert!(!normalise_inbound_node_local_overlay(&mut m));
            assert_eq!(m.lifecycle_state, st);
        }
        // A marker alone (on a visible row) is still stripped.
        let mut m = base("a", "2026-06-16T00:00:00+00:00");
        m.metadata = json!({ key: {} });
        assert!(normalise_inbound_node_local_overlay(&mut m));
        assert!(m.metadata.get(key).is_none());
    }

    #[test]
    fn title_slot_metadata_sql_names_every_node_local_key_f1_goal4() {
        let (sqlite, pg) = (
            sqlite_title_slot_newer_metadata(),
            pg_title_slot_newer_metadata(),
        );
        for key in NODE_LOCAL_METADATA_KEYS {
            assert!(sqlite.contains(&format!("'$.{key}'")), "{sqlite}");
            assert!(sqlite.contains(&format!("'{key}'")), "{sqlite}");
            assert!(pg.contains(&format!("'{key}'")), "{pg}");
        }
        assert!(pg.starts_with("((EXCLUDED.metadata - ARRAY["), "{pg}");
        assert!(pg_node_local_overlay("$15::jsonb").starts_with("(($15::jsonb - ARRAY["));
    }

    #[test]
    fn lifecycle_case_sql_twin_names_only_the_variant_b_set_3266() {
        let case = lifecycle_local_taint_wins_case("excluded", "memories");
        assert!(case.contains("memories.lifecycle_state IN ('contaminated', 'quarantined')"));
        assert!(case.contains("excluded.lifecycle_state = 'contaminated'"));
        assert!(
            !case.contains("tombstoned"),
            "tombstoned keeps newer-wins adoption (ruling variant B): {case}"
        );
    }

    #[test]
    fn merge_memory_lww_tie_breaks_on_id_deterministically() {
        // Same updated_at; the lexically-greater id wins the tiebreak.
        let mut low = base("a", "2026-06-16T00:00:00+00:00");
        low.title = "from-a".into();
        let mut high = base("b", "2026-06-16T00:00:00+00:00");
        high.title = "from-b".into();
        // Note: id mismatch would trip the debug_assert; for this test we
        // deliberately use distinct ids to exercise the tiebreak, and the
        // assertion is only that the (updated_at, id)-maximal side wins.
        // `b` > `a`, so "from-b" wins regardless of argument order.
        assert_eq!(merge_lww_title(&low, &high), "from-b");
        assert_eq!(merge_lww_title(&high, &low), "from-b");
    }

    /// Helper exercising only the LWW title pick (bypasses the
    /// same-id debug_assert so the id tiebreak can be tested directly).
    fn merge_lww_title(a: &Memory, b: &Memory) -> String {
        lww(a, b, &a.title, &b.title)
    }

    /// Set `metadata.attest_level` on a row (test helper).
    fn with_attest(mut m: Memory, level: &str) -> Memory {
        m.metadata = json!({ "attest_level": level });
        m
    }

    #[test]
    fn attest_rank_reads_metadata_level() {
        let claimed = with_attest(base("a", "2026-06-16T00:00:00+00:00"), "claimed");
        let attested = with_attest(base("a", "2026-06-16T00:00:00+00:00"), "agent_attested");
        let absent = base("a", "2026-06-16T00:00:00+00:00"); // metadata {}
        assert_eq!(attest_rank(&claimed), 0);
        assert_eq!(attest_rank(&attested), 1);
        assert_eq!(attest_rank(&absent), 0);
    }

    #[test]
    fn merge_tiebreak_prefers_higher_attest_rank_on_updated_at_tie() {
        // Same id, same updated_at — the attested row must win the LWW
        // tiebreak ahead of the lexical-id fallback, regardless of order.
        let mut local = with_attest(base("a", "2026-06-16T00:00:00+00:00"), "agent_attested");
        local.title = "attested".into();
        let mut remote = with_attest(base("a", "2026-06-16T00:00:00+00:00"), "claimed");
        remote.title = "unsigned".into();

        assert_eq!(merge_memory(&local, &remote).title, "attested");
        // Commutative: the attested side wins regardless of argument order.
        assert_eq!(merge_memory(&remote, &local).title, "attested");
    }

    #[test]
    fn merge_updated_at_still_dominates_attest_rank() {
        // A strictly-newer unsigned edit still wins over an older attested
        // one — attest_rank only breaks an `updated_at` TIE, it is the
        // middle key, not the primary one.
        let attested_old = with_attest(base("a", "2026-06-16T00:00:00+00:00"), "agent_attested");
        let mut claimed_new = with_attest(base("a", "2026-06-16T09:00:00+00:00"), "claimed");
        claimed_new.title = "newer".into();
        assert_eq!(merge_memory(&attested_old, &claimed_new).title, "newer");
    }

    #[test]
    fn sanitize_inbound_attestation_neutralizes_self_asserted_level() {
        // A forged remote self-asserting agent_attested is reset to claimed.
        let forged = with_attest(base("a", "2026-06-16T00:00:00+00:00"), "agent_attested");
        let sanitized = sanitize_inbound_attestation(&forged);
        assert_eq!(attest_rank(&sanitized), 0);
        assert_eq!(
            sanitized
                .metadata
                .get("attest_level")
                .and_then(Value::as_str),
            Some("claimed")
        );
    }

    #[test]
    fn sanitize_inbound_attestation_leaves_absent_level_absent() {
        // A row that never carried attest_level does not gain the key.
        let no_level = base("a", "2026-06-16T00:00:00+00:00"); // metadata {}
        let sanitized = sanitize_inbound_attestation(&no_level);
        assert!(sanitized.metadata.get("attest_level").is_none());
        assert_eq!(attest_rank(&sanitized), 0);
    }

    // ---- #2863 reassert_verified_attestation --------------------------------

    /// A `base`-shaped row carrying `agent_id` + `write_signature` + a given
    /// `attest_level` (the six signed-surface fields come from `base`).
    fn signed_row_2863(sig: &str, level: &str) -> Memory {
        let mut m = base("a", "2026-06-16T00:00:00+00:00");
        m.metadata = json!({
            "agent_id": "ai:hive-author",
            "write_signature": sig,
            "attest_level": level,
        });
        m
    }

    fn level_of(m: &Memory) -> Option<&str> {
        m.metadata.get("attest_level").and_then(Value::as_str)
    }

    #[test]
    fn reassert_restores_agent_attested_on_matching_surface_2863() {
        // sanitize demoted the merged row to `claimed`, but its full SignableWrite
        // surface + write_signature equals the receiver-verified inbound → restore.
        let verified = signed_row_2863("SIG", "agent_attested");
        let merged = signed_row_2863("SIG", "claimed");
        let out = reassert_verified_attestation(merged, &verified, true);
        assert_eq!(level_of(&out), Some("agent_attested"));
    }

    #[test]
    fn reassert_noop_when_not_receiver_verified_2863() {
        // Non-receive callers pass false → byte-identical legacy merge (claimed).
        let verified = signed_row_2863("SIG", "agent_attested");
        let merged = signed_row_2863("SIG", "claimed");
        let out = reassert_verified_attestation(merged, &verified, false);
        assert_eq!(level_of(&out), Some("claimed"));
    }

    #[test]
    fn reassert_noop_on_content_surface_mismatch_2863() {
        // A Frankenstein / local-won row (different content) must stay claimed.
        let verified = signed_row_2863("SIG", "agent_attested");
        let mut merged = signed_row_2863("SIG", "claimed");
        merged.content = "DIFFERENT-CONTENT".into();
        let out = reassert_verified_attestation(merged, &verified, true);
        assert_eq!(level_of(&out), Some("claimed"));
    }

    #[test]
    fn reassert_noop_on_signature_mismatch_2863() {
        // A DIFFERENT write_signature (a distinct signed unit) must not be laundered.
        let verified = signed_row_2863("SIG-A", "agent_attested");
        let merged = signed_row_2863("SIG-B", "claimed");
        let out = reassert_verified_attestation(merged, &verified, true);
        assert_eq!(level_of(&out), Some("claimed"));
    }

    #[test]
    fn reassert_noop_when_signature_absent_2863() {
        // No write_signature on either side → fail-closed (never re-assert).
        let mut verified = base("a", "2026-06-16T00:00:00+00:00");
        verified.metadata =
            json!({ "agent_id": "ai:hive-author", "attest_level": "agent_attested" });
        let mut merged = base("a", "2026-06-16T00:00:00+00:00");
        merged.metadata = json!({ "agent_id": "ai:hive-author", "attest_level": "claimed" });
        let out = reassert_verified_attestation(merged, &verified, true);
        assert_eq!(level_of(&out), Some("claimed"));
    }

    /// Set `metadata.version_vector` from `(peer, ts)` pairs (test helper).
    fn with_clock(mut m: Memory, pairs: &[(&str, &str)]) -> Memory {
        let entries: serde_json::Map<String, Value> = pairs
            .iter()
            .map(|(p, t)| ((*p).to_string(), Value::String((*t).to_string())))
            .collect();
        m.metadata = json!({ "version_vector": { "entries": entries } });
        m
    }

    fn clock_of(m: &Memory) -> std::collections::BTreeMap<String, String> {
        parse_version_vector(&m.metadata).entries
    }

    #[test]
    fn version_vector_merges_by_pointwise_max_union() {
        // Disjoint peers both survive; a shared peer takes the later ts.
        let local = with_clock(
            base("a", "2026-06-16T00:00:00+00:00"),
            &[
                ("node-a", "2026-06-16T05:00:00+00:00"),
                ("shared", "2026-06-16T01:00:00+00:00"),
            ],
        );
        let remote = with_clock(
            base("a", "2026-06-16T00:00:01+00:00"),
            &[
                ("node-b", "2026-06-16T07:00:00+00:00"),
                ("shared", "2026-06-16T09:00:00+00:00"),
            ],
        );
        let merged = clock_of(&merge_memory(&local, &remote));
        assert_eq!(
            merged.get("node-a").map(String::as_str),
            Some("2026-06-16T05:00:00+00:00")
        );
        assert_eq!(
            merged.get("node-b").map(String::as_str),
            Some("2026-06-16T07:00:00+00:00")
        );
        // shared → the LATER timestamp (pointwise max), not a row-LWW pick.
        assert_eq!(
            merged.get("shared").map(String::as_str),
            Some("2026-06-16T09:00:00+00:00")
        );
    }

    #[test]
    fn version_vector_preserves_observation_of_lww_losing_row() {
        // The 5-agent vote (4d3ea1c5) correctness regression case: the
        // row with the OLDER updated_at LOSES the row-level LWW, yet it
        // carries a NEWER timestamp for `peer-x`. A deep-merge/LWW path
        // would discard that observation; pointwise-max MUST keep it.
        let lww_loser = with_clock(
            base("a", "2026-06-16T00:00:00+00:00"), // older updated_at (loses LWW)
            &[("peer-x", "2026-06-16T23:00:00+00:00")], // but newer peer-x obs
        );
        let lww_winner = with_clock(
            base("a", "2026-06-16T09:00:00+00:00"), // newer updated_at (wins LWW)
            &[("peer-x", "2026-06-16T02:00:00+00:00")],
        );
        let merged = clock_of(&merge_memory(&lww_winner, &lww_loser));
        // peer-x keeps the LATER (23:00) timestamp even though its carrier
        // lost the row-LWW — causal history is not lost.
        assert_eq!(
            merged.get("peer-x").map(String::as_str),
            Some("2026-06-16T23:00:00+00:00")
        );
    }

    #[test]
    fn version_vector_merge_is_commutative_and_idempotent() {
        let local = with_clock(
            base("a", "2026-06-16T00:00:00+00:00"),
            &[("node-a", "2026-06-16T05:00:00+00:00")],
        );
        let remote = with_clock(
            base("a", "2026-06-16T00:00:01+00:00"),
            &[("node-b", "2026-06-16T07:00:00+00:00")],
        );
        let ab = clock_of(&merge_memory(&local, &remote));
        let ba = clock_of(&merge_memory(&remote, &local));
        assert_eq!(ab, ba, "version_vector merge commutative");
        // Idempotent: merging a row with itself is unchanged.
        assert_eq!(clock_of(&merge_memory(&local, &local)), clock_of(&local));
    }

    #[test]
    fn stamp_version_vector_advances_local_node_entry() {
        let mut md = json!({});
        stamp_version_vector(&mut md, "node-a", "2026-06-16T05:00:00+00:00");
        assert_eq!(
            md["version_vector"]["entries"]["node-a"],
            "2026-06-16T05:00:00+00:00"
        );
        // Monotonic: an older stamp does NOT regress the entry.
        stamp_version_vector(&mut md, "node-a", "2026-06-16T01:00:00+00:00");
        assert_eq!(
            md["version_vector"]["entries"]["node-a"],
            "2026-06-16T05:00:00+00:00"
        );
        // A newer stamp advances it.
        stamp_version_vector(&mut md, "node-a", "2026-06-16T09:00:00+00:00");
        assert_eq!(
            md["version_vector"]["entries"]["node-a"],
            "2026-06-16T09:00:00+00:00"
        );
    }

    #[test]
    fn stamp_version_vector_preserves_other_node_entries() {
        // Stamping this node never touches another node's component
        // (learned via merge, not local stamping).
        let mut md =
            json!({ "version_vector": { "entries": { "node-b": "2026-06-16T03:00:00+00:00" } } });
        stamp_version_vector(&mut md, "node-a", "2026-06-16T05:00:00+00:00");
        assert_eq!(
            md["version_vector"]["entries"]["node-b"],
            "2026-06-16T03:00:00+00:00"
        );
        assert_eq!(
            md["version_vector"]["entries"]["node-a"],
            "2026-06-16T05:00:00+00:00"
        );
    }

    #[test]
    fn stamp_version_vector_empty_node_id_is_noop() {
        let mut md = json!({});
        stamp_version_vector(&mut md, "", "2026-06-16T05:00:00+00:00");
        assert!(md.get("version_vector").is_none());
    }

    #[test]
    fn stamp_version_vector_non_object_metadata_is_noop() {
        let mut md = json!("scalar-metadata");
        stamp_version_vector(&mut md, "node-a", "2026-06-16T05:00:00+00:00");
        assert_eq!(md, json!("scalar-metadata"));
    }

    #[test]
    fn version_vector_absent_on_both_stays_absent() {
        let local = base("a", "2026-06-16T00:00:00+00:00"); // metadata {}
        let remote = base("a", "2026-06-16T09:00:00+00:00");
        let merged = merge_memory(&local, &remote);
        assert!(merged.metadata.get("version_vector").is_none());
    }

    #[test]
    fn forged_remote_cannot_win_attest_tiebreak_after_sanitize() {
        // The federation-boundary contract: local is genuinely attested,
        // a forged remote self-asserts agent_attested at the same
        // updated_at. After sanitize the remote is claimed (rank 0) and
        // loses the tiebreak, so the local attested title survives.
        let mut local = with_attest(base("a", "2026-06-16T00:00:00+00:00"), "agent_attested");
        local.title = "genuine".into();
        let mut forged_remote =
            with_attest(base("a", "2026-06-16T00:00:00+00:00"), "agent_attested");
        forged_remote.title = "forged".into();

        let sanitized = sanitize_inbound_attestation(&forged_remote);
        assert_eq!(merge_memory(&local, &sanitized).title, "genuine");
        assert_eq!(merge_memory(&sanitized, &local).title, "genuine");
    }

    // ---- #1755 item 3b: inbound updated_at freshness clamp -----------

    #[test]
    fn clamp_inbound_updated_at_caps_far_future_postdate() {
        // A relayed row post-dated 1 year into the future is clamped to
        // now + skew, so it cannot win the LWW over genuinely-newer rows.
        let now = "2026-06-20T12:00:00+00:00";
        let skew = 300; // 5 min
        let postdated = base("a", "2027-06-20T12:00:00+00:00");
        let clamped = clamp_inbound_updated_at(postdated, now, skew);
        // Clamped to now + 300s = 12:05:00.
        let ceil =
            chrono::DateTime::parse_from_rfc3339(now).unwrap() + chrono::Duration::seconds(skew);
        assert_eq!(
            chrono::DateTime::parse_from_rfc3339(&clamped.updated_at).unwrap(),
            ceil
        );
    }

    #[test]
    fn clamp_inbound_updated_at_leaves_honest_timestamp_untouched() {
        // Wave-2 B14: honest updated_at at-or-before now + skew is kept
        // BYTE-VERBATIM. Canonicalization is the LWW comparison key
        // (`lww_updated_at_key`), not this clamp.
        let now = "2026-06-20T12:00:00+00:00";
        let skew = 300;
        let honest = base("a", "2026-06-20T12:00:02+00:00");
        let out = clamp_inbound_updated_at(honest, now, skew);
        assert_eq!(out.updated_at, "2026-06-20T12:00:02+00:00");
        let past = base("a", "2026-06-20T09:00:00+00:00");
        assert_eq!(
            clamp_inbound_updated_at(past, now, skew).updated_at,
            "2026-06-20T09:00:00+00:00"
        );
        // A `...Z` honest inbound is also left verbatim (not rewritten
        // to micros+Z).
        let z = base("a", "2026-06-20T12:00:02Z");
        assert_eq!(
            clamp_inbound_updated_at(z, now, skew).updated_at,
            "2026-06-20T12:00:02Z"
        );
    }

    /// Wave-1 C1: a same-wall-second inbound `...Z` claimed row must NOT
    /// beat a locally attested `...+00:00` row via string LWW.
    #[test]
    fn z_suffix_same_second_does_not_beat_attested_plus00_c1() {
        let mut local = with_attest(base("a", "2026-06-16T00:00:00+00:00"), "agent_attested");
        local.title = "attested-local".into();
        let mut remote = with_attest(base("a", "2026-06-16T00:00:00Z"), "claimed");
        remote.title = "unsigned-z".into();
        let merged = merge_memory(&local, &remote);
        assert_eq!(
            merged.title, "attested-local",
            "same-instant Z vs +00:00 must fall through to attest_rank, not string order"
        );
        let merged_rev = merge_memory(&remote, &local);
        assert_eq!(merged_rev.title, "attested-local");
    }

    #[test]
    fn clamp_inbound_updated_at_noop_on_unparseable() {
        // A malformed now or updated_at never breaks the merge — pass through.
        let garbage = base("a", "not-a-timestamp");
        assert_eq!(
            clamp_inbound_updated_at(garbage, "2026-06-20T12:00:00+00:00", 300).updated_at,
            "not-a-timestamp"
        );
        let ok = base("a", "2027-06-20T12:00:00+00:00");
        assert_eq!(
            clamp_inbound_updated_at(ok, "also-garbage", 300).updated_at,
            "2027-06-20T12:00:00+00:00"
        );
    }

    #[test]
    fn merge_memory_metadata_deep_merge_disjoint_keys_both_survive() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.metadata = json!({"k_local": 1, "nested": {"x": 1}});
        let mut remote = base("a", "2026-06-16T00:00:01+00:00");
        remote.metadata = json!({"k_remote": 2, "nested": {"y": 2}});

        let merged = merge_memory(&local, &remote);
        assert_eq!(merged.metadata["k_local"], json!(1));
        assert_eq!(merged.metadata["k_remote"], json!(2));
        // Nested object merged key-wise.
        assert_eq!(merged.metadata["nested"]["x"], json!(1));
        assert_eq!(merged.metadata["nested"]["y"], json!(2));
    }

    #[test]
    fn merge_memory_metadata_agent_id_immutable_local_wins() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.metadata = json!({"agent_id": "original-owner"});
        // Remote is NEWER and tries to rewrite agent_id.
        let mut remote = base("a", "2026-06-16T09:00:00+00:00");
        remote.metadata = json!({"agent_id": "peer-impostor"});

        let merged = merge_memory(&local, &remote);
        // Provenance is write-once: local's original agent_id survives
        // even though remote is the newer (LWW) side.
        assert_eq!(merged.metadata["agent_id"], json!("original-owner"));
    }

    #[test]
    fn merge_memory_metadata_scope_lww() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.metadata = json!({"scope": "private"});
        let mut remote = base("a", "2026-06-16T09:00:00+00:00");
        remote.metadata = json!({"scope": "collective"});
        // Remote newer ⇒ its scope wins.
        assert_eq!(
            merge_memory(&local, &remote).metadata["scope"],
            json!("collective")
        );
        // Local newer ⇒ local scope wins.
        let mut local2 = base("a", "2026-06-16T10:00:00+00:00");
        local2.metadata = json!({"scope": "private"});
        let mut remote2 = base("a", "2026-06-16T01:00:00+00:00");
        remote2.metadata = json!({"scope": "collective"});
        assert_eq!(
            merge_memory(&local2, &remote2).metadata["scope"],
            json!("private")
        );
    }

    #[test]
    fn merge_memory_metadata_governance_keeps_local() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.metadata = json!({"governance": {"write": "owner"}});
        // Remote newer, tries to weaken governance.
        let mut remote = base("a", "2026-06-16T09:00:00+00:00");
        remote.metadata = json!({"governance": {"write": "any"}});
        let merged = merge_memory(&local, &remote);
        // A merge must not let a peer rewrite governance.
        assert_eq!(merged.metadata["governance"], json!({"write": "owner"}));
    }

    #[test]
    fn merge_memory_version_max() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.version = 7;
        let mut remote = base("a", "2026-06-16T09:00:00+00:00");
        remote.version = 3;
        // Even though remote is newer by updated_at, version takes max so
        // the optimistic-concurrency counter never rolls backwards.
        assert_eq!(merge_memory(&local, &remote).version, 7);
    }

    #[test]
    fn merge_memory_reflection_depth_max() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.reflection_depth = 4;
        let mut remote = base("a", "2026-06-16T09:00:00+00:00");
        remote.reflection_depth = 1;
        assert_eq!(merge_memory(&local, &remote).reflection_depth, 4);
    }

    #[test]
    fn merge_memory_prefer_non_null_fields() {
        // local has the values, remote has None ⇒ values preserved.
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.entity_id = Some("ent-1".into());
        local.source_uri = Some("uri:doc".into());
        local.source_span = Some(SourceSpan { start: 0, end: 5 });
        local.persona_version = Some(2);
        local.confidence_decayed_at = Some("2026-06-16T00:00:00+00:00".into());

        // Remote NEWER but all None — prefer-non-null keeps local's values.
        let remote = base("a", "2026-06-16T09:00:00+00:00");

        let merged = merge_memory(&local, &remote);
        assert_eq!(merged.entity_id, Some("ent-1".into()));
        assert_eq!(merged.source_uri, Some("uri:doc".into()));
        assert_eq!(merged.source_span, Some(SourceSpan { start: 0, end: 5 }));
        assert_eq!(merged.persona_version, Some(2));
        assert_eq!(
            merged.confidence_decayed_at,
            Some("2026-06-16T00:00:00+00:00".into())
        );

        // And the symmetric case: None local + Some remote ⇒ value.
        let local_none = base("a", "2026-06-16T00:00:00+00:00");
        let mut remote_val = base("a", "2026-06-16T00:00:01+00:00");
        remote_val.entity_id = Some("ent-2".into());
        assert_eq!(
            merge_memory(&local_none, &remote_val).entity_id,
            Some("ent-2".into())
        );
    }

    #[test]
    fn merge_memory_last_accessed_at_max_with_null_floor() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.last_accessed_at = Some("2026-06-16T03:00:00+00:00".into());
        let remote = base("a", "2026-06-16T00:00:01+00:00"); // None
        // Present beats None.
        assert_eq!(
            merge_memory(&local, &remote).last_accessed_at,
            Some("2026-06-16T03:00:00+00:00".into())
        );
        // Both present ⇒ later wins.
        let mut local2 = base("a", "2026-06-16T00:00:00+00:00");
        local2.last_accessed_at = Some("2026-06-16T03:00:00+00:00".into());
        let mut remote2 = base("a", "2026-06-16T00:00:01+00:00");
        remote2.last_accessed_at = Some("2026-06-16T08:00:00+00:00".into());
        assert_eq!(
            merge_memory(&local2, &remote2).last_accessed_at,
            Some("2026-06-16T08:00:00+00:00".into())
        );
    }

    #[test]
    fn merge_memory_citations_prefer_non_empty() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.citations = vec![crate::models::memory::Citation {
            uri: "uri:a".into(),
            accessed_at: "2026-06-16T00:00:00+00:00".into(),
            hash: None,
            span: None,
        }];
        // Remote newer but empty citations — provenance preserved.
        let remote = base("a", "2026-06-16T09:00:00+00:00");
        assert_eq!(merge_memory(&local, &remote).citations.len(), 1);
    }

    #[test]
    fn merge_memory_is_idempotent() {
        // A richly-populated row merged with itself is unchanged.
        let mut m = base("a", "2026-06-16T05:00:00+00:00");
        m.tier = Tier::Mid;
        m.tags = vec!["x".into(), "y".into()];
        m.priority = 5;
        m.confidence = 0.6;
        m.access_count = 12;
        m.expires_at = Some("2026-06-20T00:00:00+00:00".into());
        m.last_accessed_at = Some("2026-06-17T00:00:00+00:00".into());
        m.metadata = json!({"agent_id": "owner", "scope": "private", "k": {"n": 1}});
        m.reflection_depth = 2;
        m.memory_kind = MemoryKind::Reflection;
        m.entity_id = Some("e".into());
        m.version = 9;
        m.lifecycle_state = LifecycleState::Active;

        let merged = merge_memory(&m, &m);
        assert_eq!(as_json(&merged), as_json(&m));
    }

    #[test]
    fn merge_memory_is_commutative() {
        // Build two divergent rows; merge(a,b) and merge(b,a) must agree.
        //
        // DESIGN NOTE — the two "keep-local" metadata sub-rules
        // (`agent_id` immutable→local, `governance`→local) are
        // INTENTIONALLY order-sensitive: they bias toward whichever
        // operand is passed as `local`, so they are commutative ONLY when
        // both replicas already agree on the value. That is the realistic
        // case for a same-`id` row (both replicas descend from the same
        // original author / owner-set governance), so this test gives both
        // rows the SAME `agent_id` and NO `governance` key. Every other
        // field resolves through a symmetric rule (max / min / union /
        // (updated_at,id)-total-order LWW / scope-LWW / prefer-non-null)
        // and therefore must be byte-identical regardless of argument
        // order — which this test asserts on the whole row.
        let mut local = base("a", "2026-06-16T02:00:00+00:00");
        local.tier = Tier::Mid;
        local.tags = vec!["x".into(), "shared".into()];
        local.priority = 3;
        local.confidence = 0.4;
        local.access_count = 20;
        local.created_at = "2026-06-16T00:00:00+00:00".into();
        local.expires_at = Some("2026-06-18T00:00:00+00:00".into());
        local.last_accessed_at = Some("2026-06-16T01:00:00+00:00".into());
        local.metadata =
            json!({"agent_id": "owner", "scope": "private", "k_local": 1, "nested": {"x": 1}});
        local.reflection_depth = 1;
        local.version = 5;
        local.entity_id = Some("ent-local".into());

        let mut remote = base("a", "2026-06-16T08:00:00+00:00");
        remote.tier = Tier::Long;
        remote.tags = vec!["shared".into(), "y".into()];
        remote.priority = 9;
        remote.confidence = 0.7;
        remote.access_count = 5;
        remote.created_at = "2026-06-16T03:00:00+00:00".into();
        remote.expires_at = Some("2026-06-25T00:00:00+00:00".into());
        remote.last_accessed_at = Some("2026-06-16T07:00:00+00:00".into());
        remote.metadata =
            json!({"agent_id": "owner", "scope": "collective", "k_remote": 2, "nested": {"y": 2}});
        remote.reflection_depth = 3;
        remote.version = 2;
        remote.title = "remote-title".into();

        let ab = merge_memory(&local, &remote);
        let ba = merge_memory(&remote, &local);

        // Tags: compare as a set (surface order is local-first by design,
        // which differs by argument; membership must match).
        let mut ab_tags = ab.tags.clone();
        let mut ba_tags = ba.tags.clone();
        ab_tags.sort();
        ba_tags.sort();
        assert_eq!(ab_tags, ba_tags);

        // Everything else (the commutative + LWW-total-order fields)
        // must be byte-identical regardless of argument order.
        let mut ab_json = as_json(&ab);
        let mut ba_json = as_json(&ba);
        // Normalise tags ordering inside the JSON for the whole-row compare.
        ab_json["tags"] = json!(ab_tags);
        ba_json["tags"] = json!(ba_tags);
        assert_eq!(ab_json, ba_json);
    }

    #[test]
    fn merge_memory_is_associative_on_max_min_union_fields() {
        // (a ∘ b) ∘ c == a ∘ (b ∘ c) for the convergent fields.
        let mut a = base("a", "2026-06-16T01:00:00+00:00");
        a.priority = 2;
        a.access_count = 3;
        a.version = 1;
        a.tags = vec!["a".into()];
        a.created_at = "2026-06-16T02:00:00+00:00".into();

        let mut b = base("a", "2026-06-16T05:00:00+00:00");
        b.priority = 8;
        b.access_count = 1;
        b.version = 4;
        b.tags = vec!["b".into()];
        b.created_at = "2026-06-16T00:00:00+00:00".into();

        let mut c = base("a", "2026-06-16T09:00:00+00:00");
        c.priority = 5;
        c.access_count = 9;
        c.version = 2;
        c.tags = vec!["c".into()];
        c.created_at = "2026-06-16T01:00:00+00:00".into();

        let left = merge_memory(&merge_memory(&a, &b), &c);
        let right = merge_memory(&a, &merge_memory(&b, &c));

        assert_eq!(left.priority, right.priority);
        assert_eq!(left.priority, 8);
        assert_eq!(left.access_count, right.access_count);
        assert_eq!(left.access_count, 9);
        assert_eq!(left.version, right.version);
        assert_eq!(left.version, 4);
        assert_eq!(left.created_at, right.created_at);
        assert_eq!(left.created_at, "2026-06-16T00:00:00+00:00");

        let mut lt = left.tags.clone();
        let mut rt = right.tags.clone();
        lt.sort();
        rt.sort();
        assert_eq!(lt, rt);
        assert_eq!(lt, vec!["a", "b", "c"]);
    }
}
