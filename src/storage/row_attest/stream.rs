//! #10116: the operation probe of the completeness verifier. Test builds
//! count each row read, attestation visit, signature check and defect-index
//! comparison per thread, so a test can hold the verifier to a linear
//! operation count; in every other build the probe is a no-op.

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
}

impl Count {
    /// Every counter, in index order.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 7] = [
        Self::AttRead,
        Self::RowRead,
        Self::AttVisit,
        Self::RowVisit,
        Self::Sig,
        Self::DefectEq,
        Self::ChainRead,
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
        }
    }
}

#[cfg(test)]
thread_local! {
    static COUNTS: [std::cell::Cell<u64>; 7] = Default::default();
    static CEILINGS: [std::cell::Cell<u64>; 7] = const { [const { std::cell::Cell::new(u64::MAX) }; 7] };
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
