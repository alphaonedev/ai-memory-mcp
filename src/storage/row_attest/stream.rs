//! #10116: the streaming completeness verifier. [`run`] reads every
//! attestation and every live row once, from a [`Source`], and keeps only
//! per-table accumulators and per-key chain state: never every row or every
//! attestation at once. Its report is the one the slice verifier of #10040
//! gave (same fields, same defect lines in the same order).
//!
//! Test builds also count each row read, attestation visit, signature check
//! and defect-index comparison per thread, so a test can hold the verifier to
//! a linear operation count; in every other build the probe is a no-op.

use super::seal::{SealRecord, SealState};
use super::{
    AnchorStatus, Attestation, DEFECT_SEAL_HEAD_ROLLED_BACK, DEFECT_SEAL_ROLLED_BACK,
    FORMAT_VERSION, LiveRow, Op, Report, Retention, STORE_ROW_TABLE, TABLES, TableSpec,
    TableVerdict, VerifyInput, ZERO_DIGEST, acc_add, acc_term, anchor, sig_defect,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// One counted verifier operation (#10116).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Count {
    /// One `row_attestations` row decoded from the database.
    AttRead,
    /// One live base-table row read from the database.
    RowRead,
    /// One attestation looked at by the verifier.
    AttVisit,
    /// One live row looked at by the verifier.
    RowVisit,
    /// One signature check.
    Sig,
    /// One comparison of two defect indexes (the row-local filter).
    DefectEq,
    /// One attestation re-read for a row chain stored out of order.
    ChainRead,
    /// One whole-table read gathered into a `Vec` (`read_attestations`,
    /// `read_rows`): never on a verify, arm or snapshot path (#10116).
    Gather,
    /// One write of an anchored seal file (#10116 J3).
    SealWrite,
}

impl Count {
    /// Every counter, in index order.
    #[cfg(test)]
    pub(crate) const ALL: [Self; COUNTERS] = [
        Self::AttRead,
        Self::RowRead,
        Self::AttVisit,
        Self::RowVisit,
        Self::Sig,
        Self::DefectEq,
        Self::ChainRead,
        Self::Gather,
        Self::SealWrite,
    ];

    #[cfg(test)]
    const fn index(self) -> usize {
        match self {
            Self::AttRead => 0,
            Self::RowRead => 1,
            Self::AttVisit => 2,
            Self::RowVisit => 3,
            Self::Sig => 4,
            Self::DefectEq => 5,
            Self::ChainRead => 6,
            Self::Gather => 7,
            Self::SealWrite => 8,
        }
    }
}

/// How many counters [`Count`] has.
#[cfg(test)]
const COUNTERS: usize = 9;

#[cfg(test)]
thread_local! {
    static COUNTS: [std::cell::Cell<u64>; COUNTERS] = Default::default();
    static CEILINGS: [std::cell::Cell<u64>; COUNTERS] =
        const { [const { std::cell::Cell::new(u64::MAX) }; COUNTERS] };
}

/// Count one `c` (a no-op outside test builds).
#[inline]
pub(crate) fn tick(c: Count) {
    #[cfg(test)]
    {
        let i = c.index();
        let n = COUNTS.with(|k| {
            let n = k[i].get().saturating_add(1);
            k[i].set(n);
            n
        });
        let ceiling = CEILINGS.with(|k| k[i].get());
        assert!(n <= ceiling, "op-count ceiling exceeded: {c:?} > {ceiling}");
    }
    #[cfg(not(test))]
    let _ = c;
}

/// The count of `c` on this thread since the last [`reset`].
#[cfg(test)]
pub(crate) fn get(c: Count) -> u64 {
    COUNTS.with(|k| k[c.index()].get())
}

/// Zero every counter and lift every ceiling on this thread.
#[cfg(test)]
pub(crate) fn reset() {
    for c in Count::ALL {
        COUNTS.with(|k| k[c.index()].set(0));
        CEILINGS.with(|k| k[c.index()].set(u64::MAX));
    }
}

/// Panic once `c` passes `n` on this thread (a named op-count ceiling).
#[cfg(test)]
pub(crate) fn set_ceiling(c: Count, n: u64) {
    CEILINGS.with(|k| k[c.index()].set(n));
}

/// #10094: the index of a row-local defect. Each comparison is counted, so
/// a quadratic membership filter shows in the probe.
#[derive(Debug, Clone, Copy, Eq)]
pub(crate) struct RowIx(pub(crate) usize);

impl PartialEq for RowIx {
    fn eq(&self, other: &Self) -> bool {
        tick(Count::DefectEq);
        self.0 == other.0
    }
}

impl std::hash::Hash for RowIx {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

/// Where [`run`] reads a store from (#10116). Each method streams its rows
/// to `f` in the order it names; a read error ends the run with that error
/// (fail closed: a cut read is never a clean verdict).
pub(crate) trait Source {
    /// The read error.
    type Error;
    /// Every attestation whose table is not one of [`TABLES`] (the store
    /// identity row among them), any order.
    fn other_atts(&mut self, f: &mut dyn FnMut(&Attestation)) -> Result<(), Self::Error>;
    /// Every attestation of `spec`, by table sequence, then id.
    fn table_atts(
        &mut self,
        spec: &'static TableSpec,
        f: &mut dyn FnMut(&Attestation),
    ) -> Result<(), Self::Error>;
    /// Every attestation of `spec` with row key `key` that is not a cutover,
    /// by row sequence, then table sequence, then id (a re-read, only for a
    /// row chain stored out of order).
    fn key_chain(
        &mut self,
        spec: &'static TableSpec,
        key: &[u8],
        f: &mut dyn FnMut(&Attestation),
    ) -> Result<(), Self::Error>;
    /// Every live row of `spec`.
    fn live_rows(
        &mut self,
        spec: &'static TableSpec,
        f: &mut dyn FnMut(&LiveRow),
    ) -> Result<(), Self::Error>;
    /// The defect line of every live row with no canonical form (#10092),
    /// in read order; asked once, after the last [`Source::live_rows`] call.
    fn non_canonical(&mut self, f: &mut dyn FnMut(String));
    /// The id high-water mark of `row_attestations`.
    ///
    /// # Errors
    ///
    /// The read error.
    fn id_high_water(&mut self) -> Result<Option<i64>, Self::Error>;
    /// Called last with the number of attestations streamed; a source that
    /// can count its table refuses a run that did not see every row.
    ///
    /// # Errors
    ///
    /// The read error, or the count mismatch.
    fn finish(&mut self, atts_seen: u64) -> Result<(), Self::Error>;
}

/// What [`run`] needs beside the source.
pub(crate) struct Ctx<'a> {
    /// The out-of-database trust anchor (A-2).
    pub(crate) anchor: &'a anchor::AnchorLoad,
    /// Decode a memories key to its id.
    pub(crate) memory_id_of_key: &'a dyn Fn(&[u8]) -> Option<String>,
    /// The anchored seal of the store.
    pub(crate) seal: &'a SealState,
}

/// The newest attestation of one row key.
struct Latest {
    id: i64,
    seq: i64,
    delete: bool,
    row_digest: Option<Vec<u8>>,
}

/// The chain state of one row key (I1: per key, never per attestation).
struct KeyState {
    /// Attestations seen for the key.
    count: i64,
    last_seq: i64,
    last_digest: Vec<u8>,
    /// Ids of the attestations at which the chain breaks, in chain order.
    breaks: Vec<i64>,
    /// A row sequence went down in table order: the chain is re-read.
    disordered: bool,
    seen_live: bool,
    latest: Latest,
}

impl KeyState {
    fn new(a: &Attestation) -> Self {
        Self {
            count: 0,
            last_seq: a.seq,
            last_digest: ZERO_DIGEST.to_vec(),
            breaks: Vec::new(),
            disordered: false,
            seen_live: false,
            latest: Latest::of(a),
        }
    }

    /// One chain link in chain order (Append retention).
    fn link(&mut self, a: &Attestation) {
        let want_seq = self.count.saturating_add(1);
        let want_prior = if self.count == 0 {
            ZERO_DIGEST.as_slice()
        } else {
            self.last_digest.as_slice()
        };
        if a.seq != want_seq || a.prior_digest != want_prior {
            self.breaks.push(a.id);
        }
        self.count = self.count.saturating_add(1);
        a.attestation_digest.clone_into(&mut self.last_digest);
    }
}

impl Latest {
    fn of(a: &Attestation) -> Self {
        Self {
            id: a.id,
            seq: a.seq,
            delete: a.op == Op::Delete.as_str(),
            row_digest: a.row_digest.clone(),
        }
    }
}

/// The store-wide state of one run.
struct Visit {
    seen: u64,
    max_id: Option<i64>,
    seal: SealRecord,
    stores: u64,
    store_id: Option<String>,
}

impl Visit {
    fn att(&mut self, a: &Attestation) {
        tick(Count::AttVisit);
        self.seen = self.seen.saturating_add(1);
        self.max_id = Some(self.max_id.map_or(a.id, |m| m.max(a.id)));
        self.seal.add(a);
    }
}

/// The lines and state of one attested table.
struct TableRun<'s> {
    spec: &'static TableSpec,
    store_id: &'s str,
    covered: String,
    anchor: &'s anchor::AnchorLoad,
    per_att: Vec<String>,
    windows: Vec<String>,
    cutover_seq: Option<i64>,
    prev: Option<(i64, i64)>,
    head: Option<(i64, Vec<u8>)>,
    count: u64,
    keys: BTreeMap<Vec<u8>, KeyState>,
}

impl TableRun<'_> {
    fn att(&mut self, a: &Attestation) {
        let t = self.spec.table;
        self.count = self.count.saturating_add(1);
        if let Some(defect) = sig_defect(a, self.anchor) {
            self.per_att.push(format!("{t}: {defect}"));
        }
        if a.store_id != self.store_id {
            self.per_att
                .push(format!("{t}: attestation {} names another store", a.id));
        }
        if a.format_version != FORMAT_VERSION || a.covered_columns != self.covered {
            self.per_att.push(format!(
                "{t}: attestation {} format or covered columns differ",
                a.id
            ));
        }
        if Op::parse(&a.op).is_none() {
            self.per_att
                .push(format!("{t}: attestation {} has unknown op {}", a.id, a.op));
        }
        if let Some((prev_id, prev_seq)) = self.prev {
            let ok = match self.spec.retention {
                Retention::Append => prev_seq.checked_add(1) == Some(a.table_seq),
                Retention::Supersede => a.table_seq > prev_seq,
            };
            if !ok {
                self.windows.push(format!(
                    "{t}: table sequence breaks between attestations {prev_id} and {}",
                    a.id
                ));
            }
        }
        self.prev = Some((a.id, a.table_seq));
        match &mut self.head {
            Some((seq, acc)) => {
                *seq = a.table_seq;
                a.table_acc.clone_into(acc);
            }
            None => self.head = Some((a.table_seq, a.table_acc.clone())),
        }
        if a.op == Op::Cutover.as_str() {
            if self.cutover_seq.is_none() {
                self.cutover_seq = Some(a.table_seq);
            }
            return;
        }
        let append = self.spec.retention == Retention::Append;
        let key = match self.keys.get_mut(a.row_key.as_slice()) {
            Some(k) => k,
            None => self
                .keys
                .entry(a.row_key.clone())
                .or_insert_with(|| KeyState::new(a)),
        };
        if a.seq >= key.latest.seq {
            key.latest = Latest::of(a);
        }
        if append && !key.disordered {
            if a.seq < key.last_seq {
                key.disordered = true;
            } else {
                key.link(a);
            }
        }
        key.last_seq = a.seq;
    }
}

/// The verdict of one store, read once from `src` (#10116), with the seal
/// marks of every attestation it read ([`SealRecord::of`] of the store). The
/// marks are the store's seal only when the report is clean; the caller
/// advances a seal on [`super::Outcome::Clean`] alone.
///
/// # Errors
///
/// The first read error of `src`; never a partial report.
pub(crate) fn run<S: Source>(src: &mut S, ctx: &Ctx<'_>) -> Result<(Report, SealRecord), S::Error> {
    let mut visit = Visit {
        seen: 0,
        max_id: None,
        seal: SealRecord::default(),
        stores: 0,
        store_id: None,
    };
    src.other_atts(&mut |a| {
        visit.att(a);
        if a.table == STORE_ROW_TABLE {
            visit.stores = visit.stores.saturating_add(1);
            if visit.store_id.is_none() {
                visit.store_id = Some(a.store_id.clone());
            }
        }
    })?;
    let store_id = match (visit.stores, visit.store_id.take()) {
        (1, Some(id)) => Ok(id),
        (0, _) => Err("row_attestations has no store-identity row"),
        _ => Err("row_attestations has more than one store-identity row"),
    };
    let store_id = match store_id {
        Ok(id) => id,
        Err(line) => {
            // No store identity: no table is judged, but every row is still
            // read (a cut read is an error) and every non-canonical row is
            // still a defect, as before.
            for spec in TABLES {
                src.table_atts(spec, &mut |a| visit.att(a))?;
                src.live_rows(spec, &mut |_| tick(Count::RowVisit))?;
            }
            let mut defects = Vec::new();
            src.non_canonical(&mut |d| defects.push(d));
            defects.push(line.to_string());
            src.finish(visit.seen)?;
            let report = Report {
                anchor: AnchorStatus::of(ctx.anchor),
                tables: BTreeMap::new(),
                store_defects: defects.clone(),
                defects,
                unverified_memories: BTreeSet::new(),
            };
            return Ok((report, visit.seal));
        }
    };
    let sealed = match ctx.seal {
        SealState::Sealed(rec) => Some(rec),
        SealState::NotSealed | SealState::Unreadable { .. } => None,
    };
    let mut lines: Vec<String> = Vec::new();
    let mut row_local: HashSet<RowIx> = HashSet::new();
    let mut tables: BTreeMap<String, TableVerdict> = BTreeMap::new();
    let mut unverified = BTreeSet::new();
    for spec in TABLES {
        let mut tr = TableRun {
            spec,
            store_id: &store_id,
            covered: spec.covered(),
            anchor: ctx.anchor,
            per_att: Vec::new(),
            windows: Vec::new(),
            cutover_seq: None,
            prev: None,
            head: None,
            count: 0,
            keys: BTreeMap::new(),
        };
        src.table_atts(spec, &mut |a| {
            visit.att(a);
            tr.att(a);
        })?;
        let verdict = tables.entry(spec.table.to_string()).or_default();
        verdict.attestations = tr.count;
        let t = spec.table;
        let Some(cutover_seq) = tr.cutover_seq else {
            lines.push(format!("{t}: no cutover watermark"));
            src.live_rows(spec, &mut |_| tick(Count::RowVisit))?;
            continue;
        };
        // A chain stored out of table order is re-read in chain order.
        if spec.retention == Retention::Append {
            for (key, k) in tr.keys.iter_mut().filter(|(_, k)| k.disordered) {
                k.count = 0;
                k.breaks.clear();
                src.key_chain(spec, key, &mut |a| {
                    tick(Count::ChainRead);
                    k.link(a);
                })?;
            }
        }
        lines.append(&mut tr.per_att);
        lines.append(&mut tr.windows);
        let head_seq = tr.head.as_ref().map_or(0, |(s, _)| *s);
        if let Some(&sealed_head) = sealed.and_then(|rec| rec.heads.get(t))
            && head_seq < sealed_head
        {
            lines.push(format!(
                "{t}: {DEFECT_SEAL_HEAD_ROLLED_BACK}: head {head_seq}, sealed {sealed_head}"
            ));
        }
        if cutover_seq != 0 {
            lines.push(format!("{t}: cutover is not the first table sequence"));
        }
        for k in tr.keys.values() {
            for id in &k.breaks {
                lines.push(format!("{t}: row chain breaks at attestation {id}"));
            }
        }
        let mut acc = ZERO_DIGEST;
        let mut attested_acc = ZERO_DIGEST;
        let mut drifted = false;
        src.live_rows(spec, &mut |row| {
            tick(Count::RowVisit);
            acc = acc_add(&acc, &acc_term(t, &row.key, &row.digest));
            let latest = tr.keys.get_mut(row.key.as_slice()).map(|k| {
                k.seen_live = true;
                &k.latest
            });
            if let Some(attested) = latest
                .filter(|l| !l.delete)
                .and_then(|l| l.row_digest.as_deref())
                .and_then(|r| <[u8; 32]>::try_from(r).ok())
            {
                attested_acc = acc_add(&attested_acc, &acc_term(t, &row.key, &attested));
            }
            let line = match latest {
                Some(l) if l.delete => format!("{t}: live row has a delete as latest attestation"),
                Some(l) if l.row_digest.as_deref() == Some(&row.digest[..]) => {
                    verdict.verified += 1;
                    return;
                }
                Some(l) => format!("{t}: live row differs from its latest attestation {}", l.id),
                None => format!("{t}: live row has no attestation"),
            };
            drifted = true;
            row_local.insert(RowIx(lines.len()));
            lines.push(line);
            if t == "memories"
                && let Some(id) = (ctx.memory_id_of_key)(&row.key)
            {
                unverified.insert(id);
            }
        })?;
        for k in tr.keys.values() {
            if !k.latest.delete && !k.seen_live {
                lines.push(format!(
                    "{t}: attested row is gone without a delete attestation"
                ));
            }
        }
        if let Some((seq, table_acc)) = &tr.head
            && *table_acc != acc
        {
            if drifted && *table_acc == attested_acc {
                row_local.insert(RowIx(lines.len()));
            }
            lines.push(format!(
                "{t}: live rows do not match the signed table head (table_seq {seq})"
            ));
        }
    }
    let mut defects: Vec<String> = Vec::new();
    src.non_canonical(&mut |d| defects.push(d));
    let high_water = src.id_high_water()?;
    src.finish(visit.seen)?;
    let max_id = visit.max_id;
    if max_id != high_water {
        defects.push(format!(
            "row_attestations tail truncated: newest id {max_id:?}, high-water {high_water:?}"
        ));
    }
    if let SealState::Unreadable { path, why } = ctx.seal {
        defects.push(format!(
            "the anchored seal {} cannot be read: {why}",
            path.display()
        ));
    }
    if let Some(rec) = sealed
        && max_id.unwrap_or(0) < rec.high_water
    {
        defects.push(format!(
            "{DEFECT_SEAL_ROLLED_BACK}: newest id {max_id:?}, sealed {}",
            rec.high_water
        ));
    }
    let offset = defects.len();
    defects.append(&mut lines);
    let store_defects = defects
        .iter()
        .enumerate()
        .filter(|(i, _)| {
            i.checked_sub(offset)
                .is_none_or(|rel| !row_local.contains(&RowIx(rel)))
        })
        .map(|(_, x)| x.clone())
        .collect();
    let report = Report {
        anchor: AnchorStatus::of(ctx.anchor),
        tables,
        defects,
        unverified_memories: unverified,
        store_defects,
    };
    Ok((report, visit.seal))
}

/// The slice adapter of [`run`]: a store already held in memory (the unit
/// tests and the `PostgreSQL` caller of [`super::verify`]).
pub(crate) struct SliceSource<'a> {
    input: &'a VerifyInput<'a>,
    others: Vec<&'a Attestation>,
    buckets: Vec<Vec<&'a Attestation>>,
    live: Vec<Vec<&'a LiveRow>>,
    /// Per table, the non-cutover attestations by (row key, seq), built on
    /// the first out-of-order chain.
    chains: Vec<Option<Vec<&'a Attestation>>>,
}

impl<'a> SliceSource<'a> {
    /// Bucket `input` by table (stable, so equal table sequences keep their
    /// input order).
    pub(crate) fn new(input: &'a VerifyInput<'a>) -> Self {
        let index: HashMap<&str, usize> = TABLES
            .iter()
            .enumerate()
            .map(|(i, s)| (s.table, i))
            .collect();
        let mut others = Vec::new();
        let mut buckets: Vec<Vec<&'a Attestation>> = TABLES.iter().map(|_| Vec::new()).collect();
        for a in input.attestations {
            match index
                .get(a.table.as_str())
                .and_then(|&i| buckets.get_mut(i))
            {
                Some(b) => b.push(a),
                None => others.push(a),
            }
        }
        for b in &mut buckets {
            b.sort_by_key(|a| a.table_seq);
        }
        let mut live: Vec<Vec<&'a LiveRow>> = TABLES.iter().map(|_| Vec::new()).collect();
        for r in input.live {
            if let Some(b) = index.get(r.table.as_str()).and_then(|&i| live.get_mut(i)) {
                b.push(r);
            }
        }
        Self {
            input,
            others,
            buckets,
            live,
            chains: TABLES.iter().map(|_| None).collect(),
        }
    }

    fn slot(spec: &TableSpec) -> Option<usize> {
        TABLES.iter().position(|s| s.table == spec.table)
    }
}

impl Source for SliceSource<'_> {
    type Error = std::convert::Infallible;

    fn other_atts(&mut self, f: &mut dyn FnMut(&Attestation)) -> Result<(), Self::Error> {
        for a in &self.others {
            f(a);
        }
        Ok(())
    }

    fn table_atts(
        &mut self,
        spec: &'static TableSpec,
        f: &mut dyn FnMut(&Attestation),
    ) -> Result<(), Self::Error> {
        if let Some(b) = Self::slot(spec).and_then(|i| self.buckets.get(i)) {
            for a in b {
                f(a);
            }
        }
        Ok(())
    }

    fn key_chain(
        &mut self,
        spec: &'static TableSpec,
        key: &[u8],
        f: &mut dyn FnMut(&Attestation),
    ) -> Result<(), Self::Error> {
        let Some(i) = Self::slot(spec) else {
            return Ok(());
        };
        let (Some(slot), Some(bucket)) = (self.chains.get_mut(i), self.buckets.get(i)) else {
            return Ok(());
        };
        let chain = slot.get_or_insert_with(|| {
            let mut c: Vec<&Attestation> = bucket
                .iter()
                .copied()
                .filter(|a| a.op != Op::Cutover.as_str())
                .collect();
            c.sort_by(|x, y| x.row_key.cmp(&y.row_key).then(x.seq.cmp(&y.seq)));
            c
        });
        let lo = chain.partition_point(|a| a.row_key.as_slice() < key);
        let hi = chain.partition_point(|a| a.row_key.as_slice() <= key);
        for a in chain.get(lo..hi).unwrap_or_default() {
            f(a);
        }
        Ok(())
    }

    fn live_rows(
        &mut self,
        spec: &'static TableSpec,
        f: &mut dyn FnMut(&LiveRow),
    ) -> Result<(), Self::Error> {
        if let Some(b) = Self::slot(spec).and_then(|i| self.live.get(i)) {
            for r in b {
                f(r);
            }
        }
        Ok(())
    }

    fn non_canonical(&mut self, f: &mut dyn FnMut(String)) {
        for nc in self.input.non_canonical {
            f(nc.to_string());
        }
    }

    fn id_high_water(&mut self) -> Result<Option<i64>, Self::Error> {
        Ok(self.input.id_high_water)
    }

    fn finish(&mut self, _atts_seen: u64) -> Result<(), Self::Error> {
        Ok(())
    }
}
