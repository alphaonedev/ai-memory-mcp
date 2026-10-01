// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #4030 / #4031 — the temporal order and the PER-FIELD clocks the
//! CRDT-lite merge ([`super::crdt_merge::merge_memory`]) needs to be a real
//! join (commutative, associative, idempotent on distinct clocks — on the
//! merged VALUES; see `crdt_merge`'s module docs for the equal-clock
//! residuals and why the clock-map BYTES are not convergent).
//!
//! **The clock map is untrusted input (f2r review).** A peer ships its map
//! inside `metadata`. Leaves are honoured only while the value still has the
//! recorded fingerprint and are capped at the carrying row's clock (a forged
//! leaf can only make the forger's own value lose); floors are honoured only
//! where they are consistent with the values the same side carries (see
//! `Side::retain_consistent_floors`), so a forged floor cannot prune the
//! other side's nested objects, and `H v H == H` holds for any `H`.
//!
//! **Persisted representation.** The map is stored inside the row's
//! `metadata` JSON (sqlite `metadata` TEXT, postgres `metadata` JSONB): no
//! new column or schema version. It replicates with the row on every
//! federation lane and is visible to readers of `metadata`.
//!
//! # #4030 — one instant order for every timestamp the merge compares
//!
//! Content LWW compared PARSED instants while the merged row's `updated_at`
//! was chosen by comparing the raw RFC3339 STRINGS. With a non-UTC offset the
//! two disagreed (`10:00+02:00` is 08:00 UTC but sorts after `09:00Z`), so the
//! merge kept the newer content but stamped the OLDER clock, and a later stale
//! edit then beat the regressed clock and overwrote newer content. Every
//! timestamp the merge orders (`updated_at` max, `created_at` min,
//! `last_accessed_at` max, `expires_at` max) now goes through [`temporal_cmp`]:
//! parsed instant first (microsecond precision — the resolution postgres
//! `TIMESTAMPTZ` stores, so both backends order identically), raw bytes only as
//! the deterministic tie-break. The winning value keeps its ORIGINAL bytes
//! (signed genesis fields such as `created_at` are never re-rendered).
//!
//! # #4031 — a retained value keeps its own clock
//!
//! The deep metadata merge keeps a key present on only one side, and the
//! optional provenance fields keep a present value over an absent one. Before
//! #4031 such a RETAINED value silently inherited the merged row's newer clock
//! (the row-level `updated_at` max), so it then beat a genuinely newer value
//! for the same key: `merge(merge(A,C),B) != merge(A,merge(C,B))` for
//! `A{k=old}@t1`, `B{k=new}@t2`, `C{}@t3`. Federated replicas that saw the
//! same versions in different orders diverged.
//!
//! The fix is an LWW-element map with per-path versions. Each metadata node
//! (a key at any depth) and each optional field has a VERSION: by default the
//! row's `updated_at`; when a merge retains a value OLDER than the merged row,
//! its true version is recorded in the reserved metadata key
//! [`super::field_names::CRDT_FIELD_CLOCKS`] together with a fingerprint of the
//! value. A recorded version is honoured only while the value still has that
//! fingerprint, so a later LOCAL edit of the value (which never touches the
//! clock map) automatically reverts it to the row clock — no writer outside the
//! merge has to know the map exists. A recorded version is also capped at the
//! row clock, so a forged entry can only make a value LOSE.
//!
//! The whole map is additionally BOUND to the row clock it was minted at
//! (sub-key `row`): it is honoured only while the carrying row's `updated_at`
//! still denotes that instant. Any later local write stamps a new
//! `updated_at`, so the map it carries along (a read-modify-write client
//! round-trips the key verbatim) is ignored and every value in that row takes
//! the write's clock — the write re-asserted the whole row. Without the
//! binding a value edited away and then back (`private` -> `collective` ->
//! `private`) matched its recorded fingerprint again and resurrected the OLD
//! version, so a stale replay of the intermediate `collective` row beat the
//! owner's newest `private` edit (a visibility widening on the
//! authorization-bearing `metadata.scope`).
//!
//! Collisions pick the greater `(version, fingerprint)`. An object that beats
//! a scalar at the same path records the scalar's version as that path's
//! FLOOR, and every descendant older than a floor is pruned — the scalar had
//! overwritten it — which keeps object/scalar type flips associative too.
//!
//! Absence is still never a deletion (the #224 preservation promise): a key
//! missing on one side survives, now with its own clock.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use chrono::{DateTime, SubsecRound, Utc};
use serde_json::{Map, Value};

use super::field_names;

/// Format version of the [`field_names::CRDT_FIELD_CLOCKS`] object.
const CLOCKS_FORMAT: u64 = 1;
/// Sub-key: per-path `[version, fingerprint]` entries.
const CLOCKS_LEAF: &str = "leaf";
/// Sub-key: per-path floors (version of a scalar an object superseded).
const CLOCKS_FLOOR: &str = "floor";
/// Sub-key: format version.
const CLOCKS_V: &str = "v";
/// Sub-key: the row clock (`updated_at` instant) the map was minted at. A map
/// whose `row` differs from the carrying row's clock is stale (a local write
/// happened since the merge that minted it) and is ignored whole.
const CLOCKS_ROW: &str = "row";
/// Fingerprint recorded for a versioned ABSENCE of a visibility key (never a
/// 16-hex-digit value fingerprint, so it cannot collide with one).
const ABSENT_FP: &str = "absent";
/// Path prefix of an optional TOP-LEVEL field (never collides with a
/// metadata JSON-pointer path, which always starts with `/`).
const FIELD_PATH_PREFIX: char = '#';

/// #4030 — the instant a timestamp string denotes, truncated to microseconds
/// (postgres `TIMESTAMPTZ` resolution, so sqlite and postgres agree).
/// `None` for an unparseable string.
#[must_use]
pub fn instant_of(ts: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|dt| dt.with_timezone(&Utc).trunc_subsecs(6))
}

/// #4030 — the ONE total order over timestamp strings the merge uses:
/// parsed instant first (an unparseable value sorts before every parseable
/// one), raw bytes as the deterministic tie-break.
#[must_use]
pub fn temporal_cmp(a: &str, b: &str) -> Ordering {
    (instant_of(a), a).cmp(&(instant_of(b), b))
}

/// #4030 — the temporally LATER of two timestamp strings (original bytes).
#[must_use]
pub fn later<'a>(a: &'a str, b: &'a str) -> &'a str {
    if temporal_cmp(b, a).is_gt() { b } else { a }
}

/// #4030 — the temporally EARLIER of two timestamp strings (original bytes).
#[must_use]
pub fn earlier<'a>(a: &'a str, b: &'a str) -> &'a str {
    if temporal_cmp(b, a).is_lt() { b } else { a }
}

/// A per-path version: a microsecond-truncated UTC instant.
type Ver = DateTime<Utc>;

/// The row clock of a side: its `updated_at` instant, or the minimum
/// representable instant when unparseable (such a row loses every collision).
fn row_ver(updated_at: &str) -> Ver {
    instant_of(updated_at).unwrap_or(DateTime::<Utc>::MIN_UTC)
}

/// Deterministic, key-order-independent JSON rendering (objects with sorted
/// keys), so a fingerprint is stable across backends (postgres `jsonb`
/// reorders keys) and serde feature sets.
fn canonical_json(v: &Value, out: &mut String) {
    match v {
        Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                canonical_json(&map[k], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_json(item, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

/// 64-bit fingerprint (hex) of a JSON value's canonical rendering.
fn fingerprint(v: &Value) -> String {
    let mut s = String::new();
    canonical_json(v, &mut s);
    let hash = blake3::hash(s.as_bytes());
    hash.to_hex().as_str()[..16].to_string()
}

/// JSON-pointer child path (`~` -> `~0`, `/` -> `~1`).
fn child_path(parent: &str, key: &str) -> String {
    let escaped = key.replace('~', "~0").replace('/', "~1");
    format!("{parent}/{escaped}")
}

/// The parsed clock map of one row.
#[derive(Debug, Default, Clone)]
struct Clocks {
    leaf: BTreeMap<String, (Ver, String)>,
    floor: BTreeMap<String, Ver>,
}

impl Clocks {
    /// Tolerant parse of `metadata[CRDT_FIELD_CLOCKS]`: anything malformed is
    /// ignored (the value then simply carries the row clock — the pre-#4031
    /// behaviour, never an error). A map not bound to `row` — the carrying
    /// row's own clock — is STALE (minted before a later local write) or
    /// unbound, and is ignored whole: every value then carries the row clock.
    fn parse(metadata: &Value, row: Ver) -> Self {
        let mut clocks = Self::default();
        let Some(obj) = metadata
            .get(field_names::CRDT_FIELD_CLOCKS)
            .and_then(Value::as_object)
        else {
            return clocks;
        };
        let minted_at = obj
            .get(CLOCKS_ROW)
            .and_then(Value::as_str)
            .and_then(instant_of);
        if minted_at != Some(row) {
            return clocks;
        }
        if let Some(leaf) = obj.get(CLOCKS_LEAF).and_then(Value::as_object) {
            for (path, entry) in leaf {
                if let Some([at, fp]) = entry.as_array().map(Vec::as_slice)
                    && let (Some(at), Some(fp)) = (at.as_str().and_then(instant_of), fp.as_str())
                {
                    clocks.leaf.insert(path.clone(), (at, fp.to_string()));
                }
            }
        }
        if let Some(floor) = obj.get(CLOCKS_FLOOR).and_then(Value::as_object) {
            for (path, at) in floor {
                if let Some(at) = at.as_str().and_then(instant_of) {
                    clocks.floor.insert(path.clone(), at);
                }
            }
        }
        clocks
    }

    fn is_empty(&self) -> bool {
        self.leaf.is_empty() && self.floor.is_empty()
    }

    fn encode(&self, row: Ver) -> Value {
        let render = |v: &Ver| crate::validate::render_canonical_utc(*v);
        let leaf: Map<String, Value> = self
            .leaf
            .iter()
            .map(|(p, (at, fp))| {
                (
                    p.clone(),
                    Value::Array(vec![Value::String(render(at)), Value::String(fp.clone())]),
                )
            })
            .collect();
        let floor: Map<String, Value> = self
            .floor
            .iter()
            .map(|(p, at)| (p.clone(), Value::String(render(at))))
            .collect();
        let mut obj = Map::new();
        obj.insert(CLOCKS_V.to_string(), Value::from(CLOCKS_FORMAT));
        obj.insert(CLOCKS_ROW.to_string(), Value::String(render(&row)));
        if !leaf.is_empty() {
            obj.insert(CLOCKS_LEAF.to_string(), Value::Object(leaf));
        }
        if !floor.is_empty() {
            obj.insert(CLOCKS_FLOOR.to_string(), Value::Object(floor));
        }
        Value::Object(obj)
    }
}

/// One operand of a merge: its clock map and row clock.
struct Side {
    clocks: Clocks,
    row: Ver,
    /// The row's attestation rank — the #1719 3a tie-break between two
    /// values of EQUAL version (a verified row's value wins the tie).
    rank: u8,
}

impl Side {
    fn of(metadata: &Value, updated_at: &str, rank: u8) -> Self {
        let row = row_ver(updated_at);
        let mut side = Self {
            clocks: Clocks::parse(metadata, row),
            row,
            rank,
        };
        side.retain_consistent_floors(metadata);
        side
    }

    /// f2r review — a peer-supplied clock map is UNTRUSTED structure. A floor
    /// records that a scalar superseded the subtree at `path`; it is honoured
    /// only where it is consistent with the values this same side carries:
    ///
    /// * the path must exist in this side's metadata (a floor at a path the
    ///   sender does not hold would prune the OTHER side's subtree — a forged
    ///   erasure of a nested object the sender never wrote);
    /// * at an object, every descendant must be at least as new as the floor
    ///   (an honest merge pruned anything older, so an older descendant
    ///   proves the floor forged — and honouring it broke `H v H == H`);
    /// * at a scalar, the floor cannot exceed the scalar's own version.
    ///
    /// An inconsistent floor is dropped (the value keeps the version the
    /// leaves / row clock give it), never an error.
    fn retain_consistent_floors(&mut self, metadata: &Value) {
        let floors = std::mem::take(&mut self.clocks.floor);
        for (path, at) in floors {
            let at_capped = at.min(self.row);
            let Some(v) = path
                .starts_with('/')
                .then(|| metadata.pointer(&path))
                .flatten()
            else {
                continue;
            };
            let consistent = match v {
                Value::Object(map) => map.iter().all(|(k, child)| {
                    self.subtree_at_least(&child_path(&path, k), child, at_capped)
                }),
                scalar => at_capped <= self.own_ver(&path, scalar),
            };
            if consistent {
                self.clocks.floor.insert(path, at);
            }
        }
    }

    /// No node of the subtree rooted at `path` would be pruned by a floor of
    /// `min` (the exact survival rule of `merge_object_or_flip`): a scalar
    /// survives when its own version is at least `min`; an object when every
    /// child survives and it is not an EMPTY object older than `min`.
    fn subtree_at_least(&self, path: &str, v: &Value, min: Ver) -> bool {
        match v {
            Value::Object(m) => {
                (!m.is_empty() || self.own_ver(path, v) >= min)
                    && m.iter()
                        .all(|(k, c)| self.subtree_at_least(&child_path(path, k), c, min))
            }
            scalar => self.own_ver(path, scalar) >= min,
        }
    }

    /// The version of the ABSENCE of a visibility key at `path`: its recorded
    /// version when the clock map carries an absence entry there (capped at
    /// the row clock), else the row clock — the row was written without it.
    fn absent_ver(&self, path: &str) -> Ver {
        match self.clocks.leaf.get(path) {
            Some((at, fp)) if fp == ABSENT_FP => (*at).min(self.row),
            _ => self.row,
        }
    }

    /// The version of the node itself: its recorded version when the value
    /// still carries the recorded fingerprint (capped at the row clock), else
    /// the row clock (the value was written — or rewritten — with the row).
    fn own_ver(&self, path: &str, v: &Value) -> Ver {
        match self.clocks.leaf.get(path) {
            Some((at, fp)) if *fp == fingerprint(v) => (*at).min(self.row),
            _ => self.row,
        }
    }

    /// The version of a node including its subtree (an object is as new as
    /// its newest descendant).
    fn node_ver(&self, path: &str, v: &Value) -> Ver {
        let own = self.own_ver(path, v);
        match v {
            Value::Object(map) => map.iter().fold(own, |acc, (k, child)| {
                acc.max(self.node_ver(&child_path(path, k), child))
            }),
            _ => own,
        }
    }

    fn floor(&self, path: &str) -> Option<Ver> {
        self.clocks.floor.get(path).map(|f| (*f).min(self.row))
    }
}

/// Merge context for one `merge_memory` call: both sides and the clock map
/// being built for the merged row.
pub(super) struct FieldClockMerge {
    local: Side,
    remote: Side,
    /// The merged row's clock (the later of the two `updated_at`).
    row_out: Ver,
    out: Clocks,
}

/// A merged node.
struct Merged {
    value: Value,
    ver: Ver,
}

fn max_opt(a: Option<Ver>, b: Option<Ver>) -> Option<Ver> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (x, None) => x,
        (None, y) => y,
    }
}

impl FieldClockMerge {
    /// `*_rank` is each operand's attestation rank (the equal-version
    /// tie-break, same as the row-level LWW order).
    pub(super) fn new(
        local_meta: &Value,
        local_updated_at: &str,
        local_rank: u8,
        remote_meta: &Value,
        remote_updated_at: &str,
        remote_rank: u8,
    ) -> Self {
        let local = Side::of(local_meta, local_updated_at, local_rank);
        let remote = Side::of(remote_meta, remote_updated_at, remote_rank);
        let row_out = local.row.max(remote.row);
        Self {
            local,
            remote,
            row_out,
            out: Clocks::default(),
        }
    }

    /// Record a node's version when it is older than the merged row clock
    /// (a node AT the row clock needs no entry — that is the default).
    fn record(&mut self, path: &str, value: &Value, ver: Ver) {
        if ver < self.row_out {
            self.out
                .leaf
                .insert(path.to_string(), (ver, fingerprint(value)));
        }
    }

    fn record_floor(&mut self, path: &str, floor: Option<Ver>) {
        if let Some(f) = floor {
            self.out.floor.insert(path.to_string(), f);
        }
    }

    /// Merge one metadata node. `inherited` is the greatest floor of any
    /// ancestor: a node older than it was overwritten by an ancestor scalar
    /// and is pruned.
    fn merge_node(
        &mut self,
        path: &str,
        l: Option<&Value>,
        r: Option<&Value>,
        inherited: Option<Ver>,
    ) -> Option<Merged> {
        if l.is_some_and(Value::is_object) || r.is_some_and(Value::is_object) {
            self.merge_object_or_flip(path, l, r, inherited)
        } else {
            self.merge_scalars(path, l, r, inherited)
        }
    }

    /// Both present values are non-objects (or one side is absent).
    fn merge_scalars(
        &mut self,
        path: &str,
        l: Option<&Value>,
        r: Option<&Value>,
        inherited: Option<Ver>,
    ) -> Option<Merged> {
        let lv = l.map(|v| (self.local.own_ver(path, v), self.local.rank, v));
        let rv = r.map(|v| (self.remote.own_ver(path, v), self.remote.rank, v));
        let (ver, _, value) = match (lv, rv) {
            (Some(a), Some(b)) => pick_greater(a, b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => return None,
        };
        // Keep the floor history monotone even while the path holds a scalar.
        let floor = max_opt(self.local.floor(path), self.remote.floor(path));
        self.record_floor(path, floor);
        if inherited.is_some_and(|f| ver < f) {
            return None;
        }
        let value = value.clone();
        self.record(path, &value, ver);
        Some(Merged { value, ver })
    }

    /// At least one side holds an object at `path`.
    fn merge_object_or_flip(
        &mut self,
        path: &str,
        l: Option<&Value>,
        r: Option<&Value>,
        inherited: Option<Ver>,
    ) -> Option<Merged> {
        let mut floor = max_opt(self.local.floor(path), self.remote.floor(path));
        // Object vs scalar: the greater (version, fingerprint) wins; a
        // winning object records the loser scalar's version as its floor.
        let flip = match (l, r) {
            (Some(lo), Some(rs)) if lo.is_object() && !rs.is_object() => Some((
                (self.local.node_ver(path, lo), self.local.rank),
                (self.remote.own_ver(path, rs), self.remote.rank, rs),
                true,
            )),
            (Some(ls), Some(ro)) if ro.is_object() && !ls.is_object() => Some((
                (self.remote.node_ver(path, ro), self.remote.rank),
                (self.local.own_ver(path, ls), self.local.rank, ls),
                false,
            )),
            _ => None,
        };
        let (l_obj, r_obj) = match flip {
            Some(((obj_ver, obj_rank), (scalar_ver, scalar_rank, scalar), obj_is_local)) => {
                let obj = if obj_is_local { l } else { r }.unwrap_or(&Value::Null);
                if (scalar_ver, scalar_rank, fingerprint(scalar))
                    > (obj_ver, obj_rank, fingerprint(obj))
                {
                    // The scalar wins the path outright.
                    self.record_floor(path, floor);
                    if inherited.is_some_and(|f| scalar_ver < f) {
                        return None;
                    }
                    let value = scalar.clone();
                    self.record(path, &value, scalar_ver);
                    return Some(Merged {
                        value,
                        ver: scalar_ver,
                    });
                }
                floor = max_opt(floor, Some(scalar_ver));
                if obj_is_local { (l, None) } else { (None, r) }
            }
            None => (l.filter(|v| v.is_object()), r.filter(|v| v.is_object())),
        };
        self.record_floor(path, floor);
        let own = match (l_obj, r_obj) {
            (Some(a), Some(b)) => self
                .local
                .own_ver(path, a)
                .max(self.remote.own_ver(path, b)),
            (Some(a), None) => self.local.own_ver(path, a),
            (None, Some(b)) => self.remote.own_ver(path, b),
            (None, None) => return None,
        };
        let (l_map, r_map) = (
            l_obj.and_then(Value::as_object),
            r_obj.and_then(Value::as_object),
        );
        let child_floor = max_opt(inherited, floor);
        let mut keys: Vec<&String> = l_map
            .into_iter()
            .flat_map(Map::keys)
            .chain(r_map.into_iter().flat_map(Map::keys))
            .collect();
        keys.sort();
        keys.dedup();
        let mut out = Map::new();
        let mut ver = own;
        for key in keys {
            let cp = child_path(path, key);
            if let Some(m) = self.merge_node(
                &cp,
                l_map.and_then(|m| m.get(key)),
                r_map.and_then(|m| m.get(key)),
                child_floor,
            ) {
                ver = ver.max(m.ver);
                out.insert(key.clone(), m.value);
            }
        }
        if inherited.is_some_and(|f| ver < f) {
            return None;
        }
        let value = Value::Object(out);
        self.record(path, &value, own);
        Some(Merged { value, ver })
    }

    /// #4031 — merge the generic (non-special) top-level metadata keys of
    /// both sides. `skip` names the keys the caller resolves itself.
    ///
    /// f2r review — the `absence_versioned` keys (the visibility keys) treat
    /// ABSENCE as a value with its own version: a key missing from a side was
    /// removed (or never set) as of that side's clock, so a NEWER absence
    /// beats an OLDER presence. For `scope` absence means owner-private and
    /// for `target_agent_id` / `recipient_agent_id` it means "not shared", so
    /// the preservation rule ("absence is never a deletion") would let a
    /// stale peer row re-widen a row its owner narrowed. Every other key
    /// keeps the #224 preservation rule.
    pub(super) fn merge_metadata_keys(
        &mut self,
        local: &Map<String, Value>,
        remote: &Map<String, Value>,
        skip: &[&str],
        absence_versioned: &[&str],
    ) -> Map<String, Value> {
        let mut keys: Vec<&str> = local
            .keys()
            .chain(remote.keys())
            .map(String::as_str)
            .chain(absence_versioned.iter().copied())
            .collect();
        keys.sort_unstable();
        keys.dedup();
        let mut out = Map::new();
        for key in keys {
            if skip.contains(&key) {
                continue;
            }
            let path = child_path("", key);
            let (l, r) = (local.get(key), remote.get(key));
            // A visibility key is a version-only register unless an operand
            // carries an object there (a forged shape: the generic join handles it).
            let register = absence_versioned.contains(&key)
                && !l.is_some_and(Value::is_object)
                && !r.is_some_and(Value::is_object);
            let merged = if register {
                self.merge_register_with_absence(&path, l, r)
            } else {
                self.merge_node(&path, l, r, None)
            };
            if let Some(m) = merged {
                out.insert(key.to_string(), m.value);
            }
        }
        out
    }

    /// A top-level key as an LWW register whose values include ABSENCE.
    /// Order: `(version, absent-first, fingerprint)` — the attestation rank is
    /// deliberately NOT part of it (f2r, rank laundering): a rank read from
    /// the merged row would let a value that landed in an attested row carry
    /// rank 1 into the next merge, making the verdict depend on the merge
    /// grouping and failing OPEN. At an exactly equal version the ABSENCE
    /// wins, so an equal-clock collision fails CLOSED (narrower) in every
    /// grouping.
    fn merge_register_with_absence(
        &mut self,
        path: &str,
        l: Option<&Value>,
        r: Option<&Value>,
    ) -> Option<Merged> {
        let cand = |side: &Side, v: Option<&Value>| match v {
            Some(v) => (side.node_ver(path, v), 0_u8, fingerprint(v)),
            None => (side.absent_ver(path), 1_u8, ABSENT_FP.to_string()),
        };
        let lc = cand(&self.local, l);
        let rc = cand(&self.remote, r);
        let floor = max_opt(self.local.floor(path), self.remote.floor(path));
        self.record_floor(path, floor);
        let (winner, value) = if rc > lc { (rc, r) } else { (lc, l) };
        let ver = winner.0;
        match value {
            Some(v) => {
                let value = v.clone();
                self.record(path, &value, ver);
                Some(Merged { value, ver })
            }
            None => {
                if ver < self.row_out {
                    self.out
                        .leaf
                        .insert(path.to_string(), (ver, ABSENT_FP.to_string()));
                }
                None
            }
        }
    }

    /// #4031 — "present beats absent, else the newer value" for an optional
    /// top-level field, with the retained value keeping its own clock.
    pub(super) fn merge_opt<T>(&mut self, field: &str, l: &Option<T>, r: &Option<T>) -> Option<T>
    where
        T: Clone + serde::Serialize,
    {
        let path = format!("{FIELD_PATH_PREFIX}{field}");
        let lv = l.as_ref().map(|v| {
            let j = serde_json::to_value(v).unwrap_or(Value::Null);
            (self.local.own_ver(&path, &j), self.local.rank, j, v)
        });
        let rv = r.as_ref().map(|v| {
            let j = serde_json::to_value(v).unwrap_or(Value::Null);
            (self.remote.own_ver(&path, &j), self.remote.rank, j, v)
        });
        let (ver, _, json, value) = match (lv, rv) {
            (Some(a), Some(b)) => {
                if (b.0, b.1, fingerprint(&b.2)) > (a.0, a.1, fingerprint(&a.2)) {
                    b
                } else {
                    a
                }
            }
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => return None,
        };
        self.record(&path, &json, ver);
        Some(value.clone())
    }

    /// The merged row's clock map, or `None` when every value is at the row
    /// clock (the map is then omitted — byte-identical to a pre-#4031 row).
    pub(super) fn finish(self) -> Option<Value> {
        (!self.out.is_empty()).then(|| self.out.encode(self.row_out))
    }
}

/// The greater of two `(version, rank, value)` candidates by `(version,
/// attestation rank, fingerprint)` — a total order that depends only on the
/// candidates, never on argument position (commutative).
fn pick_greater<'v>(a: (Ver, u8, &'v Value), b: (Ver, u8, &'v Value)) -> (Ver, u8, &'v Value) {
    if (b.0, b.1, fingerprint(b.2)) > (a.0, a.1, fingerprint(a.2)) {
        b
    } else {
        a
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn temporal_order_uses_the_instant_not_the_bytes_4030() {
        // 10:00+02:00 is 08:00Z — EARLIER than 09:00Z although it sorts later.
        assert_eq!(
            later("2026-09-26T09:00:00Z", "2026-09-26T10:00:00+02:00"),
            "2026-09-26T09:00:00Z"
        );
        assert_eq!(
            earlier("2026-09-26T09:00:00Z", "2026-09-26T10:00:00+02:00"),
            "2026-09-26T10:00:00+02:00"
        );
        // Fractional rendering variants of one instant tie on the instant and
        // break deterministically on bytes.
        let a = "2026-09-26T09:00:00.500Z";
        let b = "2026-09-26T09:00:00.5+00:00";
        assert_eq!(later(a, b), later(b, a));
    }

    #[test]
    fn clocks_round_trip_and_tolerate_garbage() {
        let mut c = Clocks::default();
        let t = instant_of("2026-01-01T00:00:00Z").expect("parse");
        c.leaf.insert("/k".to_string(), (t, "abcd".to_string()));
        c.floor.insert("/o".to_string(), t);
        let meta = json!({ field_names::CRDT_FIELD_CLOCKS: c.encode(t) });
        let back = Clocks::parse(&meta, t);
        assert_eq!(back.leaf.get("/k"), Some(&(t, "abcd".to_string())));
        assert_eq!(back.floor.get("/o"), Some(&t));
        let junk = json!({ field_names::CRDT_FIELD_CLOCKS: {"leaf": {"/k": 3}, "floor": 7} });
        assert!(Clocks::parse(&junk, t).is_empty());
    }

    #[test]
    fn a_map_minted_at_another_row_clock_is_ignored() {
        // The map is bound to the row clock it was minted at: once a local
        // write re-stamps `updated_at`, the carried map is stale and every
        // value takes the write's clock (no A-B-A fingerprint resurrection).
        let minted = instant_of("2026-01-01T00:00:00Z").expect("parse");
        let later_write = instant_of("2026-01-05T00:00:00Z").expect("parse");
        let mut c = Clocks::default();
        c.leaf
            .insert("/scope".to_string(), (minted, "abcd".to_string()));
        let meta = json!({ field_names::CRDT_FIELD_CLOCKS: c.encode(minted) });
        assert!(
            !Clocks::parse(&meta, minted).is_empty(),
            "bound map honoured"
        );
        assert!(
            Clocks::parse(&meta, later_write).is_empty(),
            "a map minted before the row's current clock is stale"
        );
        // An unbound map (no `row` sub-key, e.g. hand-authored) is ignored.
        let unbound = json!({ field_names::CRDT_FIELD_CLOCKS: {
            "v": 1, "leaf": {"/scope": ["2026-01-01T00:00:00.000000Z", "abcd"]}
        }});
        assert!(Clocks::parse(&unbound, minted).is_empty());
    }

    #[test]
    fn fingerprint_is_key_order_independent() {
        let a: Value = serde_json::from_str(r#"{"b":1,"a":[1,{"y":2,"x":1}]}"#).expect("json");
        let b: Value = serde_json::from_str(r#"{"a":[1,{"x":1,"y":2}],"b":1}"#).expect("json");
        assert_eq!(fingerprint(&a), fingerprint(&b));
        assert_ne!(fingerprint(&a), fingerprint(&json!({"b": 2})));
    }
}
