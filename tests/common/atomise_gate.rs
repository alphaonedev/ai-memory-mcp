// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8687 — a test gate for the deferred atomise worker.
//!
//! The deferred worker runs on its own OS thread and may legitimately land
//! atoms between the HTTP/MCP response and the next line of a test. A test that
//! asserts "zero atoms at response time" therefore races the worker. The
//! contract is only: the write is acknowledged, and the atoms appear within a
//! bounded wait.
//!
//! [`GatedCurator`] wraps any [`Curator`] and parks the worker inside
//! `decompose` until the test opens the gate. While the gate is closed the
//! atoms CANNOT have landed, so a test can assert "the response did not block
//! on the curator" deterministically, then open the gate and poll (with
//! [`poll_until`]) for the atoms. Take it with the `#[path]` idiom:
//!
//! ```ignore
//! #[path = "common/atomise_gate.rs"]
//! mod atomise_gate;
//! ```

#![allow(dead_code)]

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use ai_memory::atomisation::curator::{Atom, Curator, CuratorError};

/// Bounded wait for the worker to land atoms or reach the gate.
pub const ATOM_LAND_DEADLINE: Duration = Duration::from_secs(15);
/// Poll interval for [`poll_until`].
pub const ATOM_POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Ceiling on how long a parked curator waits for the gate. Only reached when
/// a test forgets to open it; the worker then proceeds instead of hanging the
/// binary at teardown.
pub const GATE_PARK_CEILING: Duration = Duration::from_secs(60);

#[derive(Default)]
struct GateState {
    open: bool,
    entered: usize,
}

/// A shared closed-by-default gate. Cloning shares the same gate.
#[derive(Clone, Default)]
pub struct AtomiseGate {
    inner: Arc<(Mutex<GateState>, Condvar)>,
}

impl AtomiseGate {
    /// A new gate, closed.
    pub fn closed() -> Self {
        Self::default()
    }

    /// Open the gate; every parked and future `decompose` call proceeds.
    pub fn open(&self) {
        let (lock, cv) = &*self.inner;
        lock.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .open = true;
        cv.notify_all();
    }

    /// Number of `decompose` calls that have reached the gate.
    pub fn entered(&self) -> usize {
        self.inner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entered
    }

    /// Block until the worker is parked at the gate (bounded by
    /// [`ATOM_LAND_DEADLINE`]); returns whether it got there.
    pub fn wait_until_entered(&self) -> bool {
        poll_until(ATOM_LAND_DEADLINE, ATOM_POLL_INTERVAL, || {
            self.entered() >= 1
        })
    }

    fn park(&self) {
        let (lock, cv) = &*self.inner;
        let mut st = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        st.entered += 1;
        let deadline = Instant::now() + GATE_PARK_CEILING;
        while !st.open {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            st = cv
                .wait_timeout(st, left)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }

    /// Guard that opens the gate on drop, so a failing assertion never leaves
    /// the worker parked.
    pub fn release_on_drop(&self) -> ReleaseOnDrop {
        ReleaseOnDrop(self.clone())
    }
}

/// Opens its gate when dropped.
pub struct ReleaseOnDrop(AtomiseGate);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.open();
    }
}

/// A [`Curator`] that parks at `gate` before delegating to `inner`.
pub struct GatedCurator {
    inner: Box<dyn Curator>,
    gate: AtomiseGate,
}

impl GatedCurator {
    pub fn new(inner: Box<dyn Curator>, gate: &AtomiseGate) -> Self {
        Self {
            inner,
            gate: gate.clone(),
        }
    }
}

impl Curator for GatedCurator {
    fn decompose(
        &self,
        body: &str,
        max_atom_tokens: u32,
        max_retries: u32,
    ) -> Result<Vec<Atom>, CuratorError> {
        self.gate.park();
        self.inner.decompose(body, max_atom_tokens, max_retries)
    }
}

/// Poll `cond` every `interval` until it holds or `deadline` elapses.
pub fn poll_until(deadline: Duration, interval: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + deadline;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= end {
            return false;
        }
        std::thread::sleep(interval);
    }
}
