// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10304: the rename closure of the census is one worklist over a rename
//! graph built once, so a chain written in any order costs linear time. The
//! table below is read by this file and by the Python scanner test
//! (`scripts/ci/tests/test_census_rows_10286.py`); every expected set in it
//! is written by hand, never read back from a closure.

use super::*;
use std::fmt::Write as _;
use std::time::{Duration, Instant};

/// The closure table: each row is a text, its seed names and the expected
/// closure.
const CLOSURE_PARITY_10304: &str = include_str!("census_closure_parity_10304.json");
/// The number of rows of [`CLOSURE_PARITY_10304`].
const CLOSURE_PARITY_ROWS_10304: usize = 25;
/// The least size of each reversed chain of the linear test.
const CHAIN_BYTES_10304: usize = 100_000;
/// The wall-clock ceiling of one reversed chain (debug build). The old
/// fixpoint took 6.2 s on a 1000-hop use chain (#10304).
const CHAIN_CEILING_10304: Duration = Duration::from_secs(5);

/// The hops of the ring of renames of the push-bound test.
const RING_HOPS_10304: usize = 64;

type ClosureRow = (String, Vec<String>, Vec<String>);

fn closure_rows() -> Vec<ClosureRow> {
    serde_json::from_str(CLOSURE_PARITY_10304).expect("the #10304 closure table is a JSON list")
}

fn closure_of(text: &str, seed: &[String]) -> BTreeSet<String> {
    let toks = lex(text);
    let prep = Prep::new(&toks);
    let seed: Vec<&str> = seed.iter().map(String::as_str).collect();
    census_pins::closure(std::slice::from_ref(&prep), &seed)
}

/// Every row's closure is its hand-written set, and equal to the old
/// fixpoint (the oracle) on the same input.
#[test]
fn closure_table_and_oracle_10304() {
    let rows = closure_rows();
    assert_eq!(
        rows.len(),
        CLOSURE_PARITY_ROWS_10304,
        "rows of the #10304 table"
    );
    let mut bad = Vec::new();
    for (i, (text, seed, want)) in rows.iter().enumerate() {
        let want: BTreeSet<String> = want.iter().cloned().collect();
        let have = closure_of(text, seed);
        if have != want {
            bad.push(format!("row {i} {text:?}: closure {have:?}, want {want:?}"));
        }
        let toks = lex(text);
        let prep = Prep::new(&toks);
        let s: Vec<&str> = seed.iter().map(String::as_str).collect();
        let oracle = census_pins::closure_fixpoint(std::slice::from_ref(&prep), &s);
        if have != oracle {
            bad.push(format!(
                "row {i} {text:?}: closure {have:?}, the fixpoint {oracle:?}"
            ));
        }
    }
    assert_eq!(bad, Vec::<String>::new(), "#10304 closure table");
}

/// A chain of `hops` renames from `name(0)` to `name(hops)`, written last
/// hop first, of at least [`CHAIN_BYTES_10304`] bytes.
fn reversed_chain(line: impl Fn(usize) -> String) -> (String, usize) {
    let mut lines = Vec::new();
    let mut bytes = 0usize;
    while bytes < CHAIN_BYTES_10304 {
        let l = line(lines.len());
        bytes += l.len();
        lines.push(l);
    }
    let hops = lines.len();
    lines.reverse();
    (lines.concat(), hops)
}

fn use_hop(i: usize) -> String {
    let mut s = String::new();
    writeln!(s, "use a{i} as a{};", i + 1).expect("writing to a String cannot fail");
    s
}

fn type_hop(i: usize) -> String {
    let mut s = String::new();
    writeln!(s, "type T{} = T{i};", i + 1).expect("writing to a String cannot fail");
    s
}

fn macro_hop(i: usize) -> String {
    let mut s = String::new();
    writeln!(s, "macro_rules! m{} {{ () => {{ m{i} }} }}", i + 1)
        .expect("writing to a String cannot fail");
    s
}

/// Reversed use-alias, type and macro chains of 100K+ bytes each close in
/// linear time and reach every hop.
#[test]
fn reversed_rename_chains_are_linear_10304() {
    for (kind, hop, first) in [
        ("use", use_hop as fn(usize) -> String, "a"),
        ("type", type_hop, "T"),
        ("macro", macro_hop, "m"),
    ] {
        let (text, hops) = reversed_chain(hop);
        assert!(text.len() >= CHAIN_BYTES_10304, "{kind} chain size");
        let seed = vec![format!("{first}0")];
        let t0 = Instant::now();
        let got = closure_of(&text, &seed);
        let dt = t0.elapsed();
        assert_eq!(got.len(), hops + 1, "{kind} chain of {hops} hops");
        assert!(
            got.contains(&format!("{first}{hops}")),
            "{kind} chain reaches its last hop"
        );
        assert!(
            dt < CHAIN_CEILING_10304,
            "reversed {kind} chain of {hops} hops took {dt:?} (#10304)"
        );
    }
}

/// The worklist pushes each node at most once: on every table row (the
/// cycles among them) and on a ring of renames, `pushes` is at most the
/// node count, and the walk ends (its loop is bounded by the node count).
#[test]
fn the_worklist_pushes_each_node_once_10304() {
    let mut bad = Vec::new();
    let mut ring = String::new();
    for i in 0..RING_HOPS_10304 {
        writeln!(ring, "use r{i} as r{};", (i + 1) % RING_HOPS_10304)
            .expect("writing to a String cannot fail");
    }
    let mut rows = closure_rows();
    rows.push((ring, vec!["r0".to_string()], Vec::new()));
    for (i, (text, seed, want)) in rows.iter().enumerate() {
        let toks = lex(text);
        let prep = Prep::new(&toks);
        let g = census_pins::RenameGraph::of(std::slice::from_ref(&prep));
        let s: Vec<&str> = seed.iter().map(String::as_str).collect();
        let r = g.reach(&s);
        if r.pushes > g.nodes() {
            bad.push(format!(
                "row {i}: {} pushes over {} nodes",
                r.pushes,
                g.nodes()
            ));
        }
        if !want.is_empty() && r.names != want.iter().cloned().collect::<BTreeSet<_>>() {
            bad.push(format!("row {i}: closure {:?}", r.names));
        }
        if want.is_empty() && r.names.len() != RING_HOPS_10304 {
            bad.push(format!(
                "ring: {} of {RING_HOPS_10304} names",
                r.names.len()
            ));
        }
    }
    assert_eq!(bad, Vec::<String>::new(), "#10304 worklist pushes");
}
