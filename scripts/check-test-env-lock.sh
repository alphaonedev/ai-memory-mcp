#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# v1.0.0 (issue #2146 -- the grep-gate half of issue #2127's Fix section,
# not delivered by PR #2142; filed by the Fable pre-merge audit of #2142).
#
# HARD-BLOCK any src/**/*.rs or tests/**/*.rs file that mutates the
# process-global $HOME environment variable (`std::env::set_var("HOME"`
# / `std::env::remove_var("HOME"`) without also referencing the
# crate-canonical `crate::config::test_env_lock()` serialization guard
# somewhere in the SAME file.
#
# WHY THIS GATE EXISTS. `std::env::set_var` is unsound under concurrent
# access -- two cargo-test threads mutating $HOME at the same time is a
# real data race, not merely a style nit. This defect class has
# recurred THREE times: #1998 -> #2115 -> #2127, each time because a
# new module hand-rolled its own module-local `static LOCK: Mutex<()>`
# instead of reusing the ONE canonical `crate::config::test_env_lock()`
# -- so two DIFFERENT modules' $HOME-mutating tests could still race
# each other cross-module even though each was individually serialized
# within its own file. PR #2142 (fix/2127-test-env-lock) migrated every
# then-existing $HOME site onto the shared lock but shipped WITHOUT the
# mechanical gate issue #2127's Fix section also specified. Issue #2146
# (the Fable audit of #2142) is that residual; this script closes it.
#
# SCOPE: FILE-scoped presence-pairing, deliberately NOT function-scoped.
# A brace-balanced per-fn scan (the naively "more precise" structural
# option) produces a real FALSE POSITIVE against this exact codebase:
# src/config.rs's test module defines a local one-line delegate
#
#     fn env_var_lock() -> std::sync::MutexGuard<'static, ()> {
#         super::test_env_lock()
#     }
#
# and several $HOME-mutating tests in that same file call
# `env_var_lock()`, never the literal token `test_env_lock` -- a
# per-fn scan would flag those as violations even though they ARE
# correctly serialized (transitively, through the delegate). File-scope
# presence-pairing has no such false positive: the delegate's OWN body
# cites `test_env_lock`, so the FILE satisfies the pairing even though
# an individual call site's tokens do not. This mirrors the Fable
# audit's own proposed fix verbatim ("file-scope grep pairing is
# sufficient at this codebase's scale: every current file with a HOME
# mutation also contains the test_env_lock token") -- verified true
# against every current site as of this gate's authorship.
#
# CLOSED-BY-#2153 RESIDUAL: the file-scope pairing above only proves the
# literal token `test_env_lock` appears SOMEWHERE in the file -- it does
# not distinguish a real call from a bare MENTION inside a `//` comment
# (issue #2153a: a file could hand-roll its own local lock while merely
# commenting "unlike test_env_lock, we use our own local mutex here" and
# still pass), nor did it catch the KNOWN RESIDUAL GAP #2146 originally
# flagged: a NEW test fn added to a file that is ALREADY compliant
# (contains test_env_lock somewhere, for its OTHER tests) hand-rolling
# its own unserialized $HOME mutation nearby -- in EITHER of two shapes:
# a nearby hand-rolled `static ... Mutex<()>` lock, OR (the #2163 Fable-
# audit residual) NO lock at all, a truly NAKED $HOME mutation. Three
# arms close both:
#
#   (a) Comment-insensitive pairing. The token search now runs over
#       comment-STRIPPED content (`//` to end-of-line removed per line,
#       mirroring the sibling stdin gate's per-line strip) before the
#       whole-file `grep -q` -- a comment-only mention of the token no
#       longer satisfies the pairing. This is a single-line strip: it
#       does not understand block comments (`/* ... */`) or a `//`
#       inside a string literal (e.g. a URL) -- both out of scope for
#       this bash gate, same bound as the stdin gate's twin.
#
#   (b) Module-local-lock adjacency arm (the #2146-proposed detector
#       arm PR #2149 did not deliver). Independent of whole-file
#       pairing, any `static <NAME>: ...Mutex<()>`-style module-local
#       lock declaration WITHIN A WINDOW_LINES-line window of a $HOME
#       mutation, with no (comment-stripped) `test_env_lock` reference
#       in that SAME window, is flagged -- even in a file that is
#       otherwise file-scope-compliant for its OTHER tests. The window
#       (not a whole-file "any local lock anywhere" check) is what lets
#       this arm coexist with src/config.rs, which legitimately declares
#       several UNRELATED module-local locks (GATE_LOCK, CAP_LOCK, and
#       test_env_lock()'s own internal static) thousands of lines away
#       from its $HOME-mutating tests -- a whole-file check would
#       false-positive there; a windowed one does not (verified against
#       the live tree at authorship).
#
#   (c) Fn-scoped naked-mutation arm (issue #2163 -- the Fable audit's
#       residual, the fn/block-scoped follow-up arm (b)'s NARROWER
#       RESIDUAL note sketched, now delivered). For each brace-balanced
#       `#[test]`-attributed fn body that mutates $HOME, the SAME fn body
#       MUST also acquire a guard: either the literal `test_env_lock`
#       token OR a call to a local delegate-wrapper fn (a fn whose own
#       body cites the token, e.g. src/config.rs's `env_var_lock()` --
#       resolved by guard_wrapper_names). A `#[test]` fn that mutates
#       $HOME with NO guard token anywhere in its own body is flagged --
#       even in a file that is file-scope-compliant for its OTHER tests,
#       and even when NO local lock declaration exists to make arm (b)
#       fire. This closes the naked-mutation shape (arm (a) passed because
#       the file has the token for its other tests; arm (b) never fired
#       because there was no local lock decl to be adjacent to). Being
#       fn-scoped rather than windowed, it neither splits a long
#       save/restore body from its guard acquisition nor consults
#       config.rs's UNRELATED module-local statics at all -- only the
#       mutating fn's OWN body matters, which is why the delegate-wrapper
#       carve-out (a `#[test]` fn calling `env_var_lock()`) is honoured
#       rather than false-positived. Scoping to `#[test]` entry points
#       (rather than every fn) is also what keeps arm (c) off the
#       legitimate RAII-guard pattern in src/recover/transcript_paths.rs,
#       where the $HOME mutation sits in a `HomeGuard::set` / `Drop::drop`
#       HELPER method serialized by its CALLER (every test acquires
#       `home_lock()` before constructing the guard), not in the `#[test]`
#       fn itself.
#
# Every one of the six production sites (src/embeddings.rs,
# src/reranker.rs, src/config.rs, src/cli/commands/config.rs,
# src/cli/rules.rs, src/recover/transcript_paths.rs) is correctly gated
# under all three arms, and any wholesale-NEW file that mutates $HOME
# without EVER mentioning test_env_lock in real code is caught
# unconditionally -- the class the issue's recurrence history
# (#1998/#2115/#2127) actually exhibited each time.
#
# NARROWER RESIDUAL (documented, not silently overclaimed): arm (c) is
# scoped to `#[test]` entry points so it does not false-positive the
# legitimate RAII-guard-HELPER pattern (a `HomeGuard::set` method
# serialized by its caller). The cost is a strictly-narrower residual: a
# naked $HOME mutation HIDDEN inside a NON-`#[test]` helper fn that a
# separate `#[test]` fn calls WITHOUT acquiring the lock would evade arm
# (c) -- but that is (i) a different, narrower shape than the #2163 naked-
# `#[test]`-fn shape it closes, (ii) equally invisible to arms (a) and
# (b), and (iii) indistinguishable by any grep gate from the legitimate
# caller-serialized RAII helper it must spare. guard_wrapper_names also
# resolves only ONE level of delegate indirection (matching the config.rs
# `env_var_lock` pattern; a wrapper-of-a-wrapper is not chased), and the
# per-line string-literal strip cannot see a multi-line raw string
# (`r#"..."#`) whose body carries an unbalanced brace -- the same
# documented bound as the sibling stdin gate's cfg_test_ranges. None of
# these shapes exists in the live tree at authorship (the clean-tree run
# is the load-bearing check).
#
# ALLOWLIST (a structural exception, not a denylist of bad patterns): a
# SEPARATE TEST BINARY that documents its own out-of-process
# serialization is exempt -- `tests/form_7_agent_external_wiring.rs`
# documents `--test-threads=1` inline and is a distinct compiled test
# target from the `src/`-embedded #[cfg(test)] cohort, so it cannot
# race those tests regardless of whether it references the crate-
# internal lock (which it structurally cannot reach -- `test_env_lock`
# is `pub(crate)`, not exported across the test-binary boundary).
#
# ARM (d) -- issue #3475 (2026-09-02). Arms (a)-(c) above police HOW a
# $HOME mutation is serialized. Arm (d) polices WHETHER a `src/**` test may
# mutate the process environment AT ALL, because #3475 proved the
# serialization answer does not generalize: a lock only helps when every
# READER takes it too, and the readers here are several hundred lib tests
# that resolve `AI_MEMORY_AGENT_ID` transitively. It is a per-file CENSUS
# RATCHET against scripts/qc-allowlists/test-env-mutation-baseline.txt -- counts may fall
# freely and never rise. Its full rationale sits with the code, below the
# arms (a)-(c) main loop.
#
# Usage:
#   scripts/check-test-env-lock.sh
#     - exit 0 on clean, exit 1 on any violation (arms (a)-(d))
#   scripts/check-test-env-lock.sh --update-baseline
#     - rewrite the arm (d) census baseline. Any number it RAISES is a
#       deliberate widening of the #3475 control and must be justified in
#       review; lowering one is always safe.
#   scripts/check-test-env-lock.sh --self-test
#     - injects: a violating fixture ($HOME mutation, zero test_env_lock
#       reference anywhere in the file), a compliant fixture (same
#       shape, but the file also references test_env_lock), a
#       hand-rolled-local-lock fixture (defines its own static
#       Mutex<()> and never references test_env_lock -- exercises the
#       #1998/#2115/#2127 recurrent class directly), a comment-only-
#       mention fixture (issue #2153a -- the token appears ONLY inside
#       a `//` comment), a module-local-lock-adjacency fixture
#       (issue #2153b -- file-scope-compliant for its FIRST test, but a
#       SECOND test >WINDOW_LINES away hand-rolls its own local lock for
#       its own $HOME mutation), a NAKED-mutation fixture (issue #2163 --
#       file-scope-compliant for its FIRST test, but a SECOND test far
#       below mutates $HOME with NO lock of any kind -- caught by arm (c)
#       only), and a DELEGATE-WRAPPER compliant fixture (issue #2163
#       over-widen guard -- a test acquiring its guard via a local
#       delegate wrapper that transitively cites the token, which arm (c)
#       must NOT false-positive), and an ARM-(d) fixture (issue #3475 -- a
#       wholly-new `src/**` file that INSTALLS a value into the
#       process-global AI_MEMORY_AGENT_ID, invisible to arms (a)-(c)
#       because it never touches $HOME); verifies the gate catches all six
#       violators and spares BOTH compliant fixtures, then cleans up.
#       Exit 0 on PASS.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Structural allowlist: files that are NOT required to reference
# test_env_lock because they run in a separately-compiled test BINARY
# with their own documented serialization discipline (see header).
ALLOWLISTED_FILES=(
    "tests/form_7_agent_external_wiring.rs"
)

is_allowlisted () {
    local rel="$1"
    local f
    for f in "${ALLOWLISTED_FILES[@]}"; do
        [[ "$rel" == "$f" ]] && return 0
    done
    return 1
}

# HOME_PATTERN matches the two mutation forms this gate cares about:
# set_var("HOME" and remove_var("HOME" (both take the literal "HOME"
# string argument). A bare read via std::env::var("HOME") is NOT a
# mutation and is intentionally NOT gated.
HOME_PATTERN='(set_var|remove_var)\("HOME"'

# The crate-canonical guard token. A file passes when this literal
# substring appears ANYWHERE in its NON-COMMENT content -- either a
# direct `crate::config::test_env_lock()` call, or (per the config.rs
# delegate pattern documented above) a local wrapper fn whose own body
# cites it.
LOCK_TOKEN='test_env_lock'

# strip_line_comments <file>
# Echoes <file> with everything from the first `//` to end-of-line
# removed on every line (issue #2153a comment-insensitivity fix, mirrors
# the sibling scripts/check-test-stdin-reads.sh per-line strip). A
# single-line heuristic: it does not understand block comments
# (`/* ... */`) and does not special-case a `//` occurring inside a
# string literal (e.g. a URL) -- both are out of scope for this bash
# gate. `LOCK_TOKEN` has no legitimate reason to appear only after a
# `//` inside a URL-bearing string in this codebase, so the residual
# false-negative surface is negligible.
strip_line_comments () {
    sed -E 's#//.*$##' "$1" 2>/dev/null
}

# WINDOW_LINES: the adjacency window (in source lines) the module-
# local-lock detector arm (issue #2153b) uses to decide whether a
# hand-rolled static lock declaration is "adjacent to" a $HOME mutation
# site, as opposed to merely co-resident somewhere else in a large file.
# src/config.rs legitimately declares several UNRELATED module-local
# locks (GATE_LOCK, CAP_LOCK, and test_env_lock()'s own internal static)
# thousands of lines away from its $HOME-mutating tests -- a whole-file
# "any local lock anywhere" check would false-positive on that file; a
# windowed check does not (the nearest unrelated static in that file is
# ~870 lines from the nearest $HOME mutation, verified at authorship).
# 50 lines comfortably covers the recurrent shape (a static declared a
# handful of lines above the #[test] fn that acquires it).
WINDOW_LINES=50

# LOCAL_LOCK_PATTERN matches a module-local lock declaration in any of
# its shapes observed in this codebase: a bare `static X: Mutex<()>`, a
# `static X: std::sync::Mutex<()>` / `StdMutex<()>` / `tokio::sync::
# Mutex<()>` alias, or an `OnceLock<Mutex<()>>`-wrapped lazy-init (all
# contain the literal substring `Mutex<()>`, which the trailing `.*`
# reaches regardless of prefix -- this also structurally covers a
# `Lazy<Mutex<()>>` (once_cell-style) shape, per issue #2153b's ask,
# even though no live site of that exact spelling exists in this repo
# today). The canonical test_env_lock() function's OWN internal
# `static LOCK: OnceLock<Mutex<()>>` self-protects against a false
# match: that declaration line sits inside the SAME function body as
# the literal `fn test_env_lock` name, so any window reaching it also
# reaches the token itself.
LOCAL_LOCK_PATTERN='static[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*:.*Mutex<\(\)>'

# guard_wrapper_names <file>
# Echoes the NAME of every local delegate-wrapper fn whose brace-balanced
# body cites the crate-canonical LOCK_TOKEN -- e.g. src/config.rs's
#
#     fn env_var_lock() -> std::sync::MutexGuard<'static, ()> {
#         super::test_env_lock()
#     }
#
# so a $HOME-mutating test that acquires its guard by CALLING env_var_lock()
# (never spelling the literal `test_env_lock` in the test fn itself) is
# recognised as serialized. This is the fn-scoped generalization of the
# config.rs delegate-wrapper carve-out the arm (c) header sketches: without
# it, the fn-scoped naked-mutation arm (c) below would false-positive every
# config.rs delegate test (~40 sites at authorship). The canonical
# `fn test_env_lock` itself is excluded (its own name IS the token). Same
# per-line lexical bounds as the sibling scans: `//` comments stripped, then
# string literals stripped before brace-counting (a multi-line raw string
# with an unbalanced brace is out of scope, the documented sibling bound).
guard_wrapper_names () {
    awk -v tok="$LOCK_TOKEN" '
    { line = $0; sub(/\/\/.*$/, "", line) }
    !active && match(line, /(^|[^A-Za-z0-9_])fn[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/) {
        name = substr(line, RSTART, RLENGTH); sub(/^.*fn[[:space:]]+/, "", name)
        active = 1; depth = 0; opened = 0; cited = 0; curname = name
    }
    active {
        if (index(line, tok) > 0) cited = 1
        counted = line; gsub(/"[^"]*"/, "", counted)
        o = gsub(/\{/, "{", counted); depth += o; if (o > 0) opened = 1
        c = gsub(/\}/, "}", counted); depth -= c
        if (opened && depth <= 0) {
            if (cited && curname != tok) print curname
            active = 0
        }
    }
    ' "$1" 2>/dev/null | sort -u
}

# naked_home_mutations <file> <guard-tokens-newline-list> <mut-linenos-csv>
# Arm (c) -- the fn-scoped naked-mutation detector (issue #2163). For each
# brace-balanced `#[test]`-attributed fn body that contains a $HOME mutation
# line (linenos passed in from the caller's grep so the mutation forms stay
# defined in ONE place, HOME_PATTERN), require the SAME fn body to also
# contain a guard token -- the canonical `test_env_lock` OR a delegate-
# wrapper name from guard_wrapper_names. A TEST fn that mutates $HOME with NO
# guard token anywhere in its own body -- an ALREADY-file-scope-compliant
# file's NEW naked test with no lock of any kind, the exact #2163 residual
# that evaded BOTH prior arms (arm (a) whole-file pairing passes because the
# file DOES contain the token for its OTHER tests; arm (b) never fires
# because there is no local lock declaration to be adjacent to) -- is
# flagged. Emits `<lineno>:<raw line>` per flagged mutation, byte-identical
# to the `grep -n` shape the other arms format, so dedup against them is
# exact. Fn-scoped (not windowed): a long save/restore body never splits a
# mutation from its guard acquisition (the window false-negative the NARROWER
# RESIDUAL note flags for arm (b) cannot arise here), and config.rs's
# UNRELATED module-local statics are irrelevant because only the mutating
# fn's OWN body is consulted.
#
# The `#[test]`-attribute scoping is what keeps arm (c) off the legitimate
# RAII-guard pattern (src/recover/transcript_paths.rs): there, the $HOME
# mutation lives in a `HomeGuard::set` / `Drop::drop` HELPER method (NOT a
# `#[test]` fn) whose serialization is the CALLER's responsibility -- every
# test constructs it only after acquiring `home_lock()` (a delegate wrapper).
# A helper method carrying no guard token in its own body is therefore NOT a
# naked test; only a `#[test]` entry point that mutates $HOME with no guard
# in its own body is the #2163 shape. A test-attribute stack (any
# `#[..::test]` / `#[test]` line, with intervening `#[..]` attributes and
# doc-comment/blank lines tolerated) is tracked so `#[tokio::test]` etc.
# count too.
naked_home_mutations () {
    awk -v tokens="$2" -v muts="$3" '
    BEGIN {
        ntok = split(tokens, T, "\n")
        nm = split(muts, M, ",")
        for (i = 1; i <= nm; i++) if (M[i] != "") is_mut[M[i] + 0] = 1
    }
    { line = $0; sub(/\/\/.*$/, "", line) }
    # Test-attribute adjacency: set the pending flag on any `#[..::test]` /
    # `#[test]` line; hold it across further `#[..]` attribute lines and
    # blank/doc-comment-stripped lines; clear it on any other real code
    # line. Only consulted when a fn signature is reached (below).
    !active && line ~ /^[[:space:]]*#\[([A-Za-z_][A-Za-z0-9_]*::)*test[]( ]/ { pending_test = 1; next }
    !active && match(line, /(^|[^A-Za-z0-9_])fn[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/) {
        active = 1; is_test = pending_test; pending_test = 0
        depth = 0; opened = 0; has_guard = 0; mc = 0
    }
    !active && line !~ /^[[:space:]]*$/ && line !~ /^[[:space:]]*#\[/ { pending_test = 0 }
    active {
        for (i = 1; i <= ntok; i++) if (T[i] != "" && index(line, T[i]) > 0) has_guard = 1
        if (is_mut[FNR]) fmut[++mc] = FNR ":" $0
        counted = line; gsub(/"[^"]*"/, "", counted)
        o = gsub(/\{/, "{", counted); depth += o; if (o > 0) opened = 1
        c = gsub(/\}/, "}", counted); depth -= c
        if (opened && depth <= 0) {
            if (is_test && !has_guard) for (i = 1; i <= mc; i++) print fmut[i]
            active = 0
        }
    }
    ' "$1" 2>/dev/null
}

# Self-test mode -- inject contrived fixtures, run the gate, confirm it
# catches the violators and spares the compliant fixture, then clean up.
if [[ "${1:-}" == "--self-test" ]]; then
    echo "Test-env-lock gate: self-test mode (contrived violations -> expect HARD-BLOCK -> cleanup)"

    probe_violation="${ROOT}/src/.check_home_lock_violation_probe.rs"
    probe_compliant="${ROOT}/src/.check_home_lock_compliant_probe.rs"
    probe_handrolled="${ROOT}/src/.check_home_lock_handrolled_probe.rs"
    probe_comment_only="${ROOT}/src/.check_home_lock_comment_only_probe.rs"
    probe_arm_b="${ROOT}/src/.check_home_lock_arm_b_probe.rs"
    probe_naked="${ROOT}/src/.check_home_lock_naked_probe.rs"
    probe_delegate="${ROOT}/src/.check_home_lock_delegate_probe.rs"
    # Arm (d) (#3475) probe. Deliberately NOT dot-prefixed: arm (d) skips
    # dot-prefixed basenames (they can never be a compiled Rust module), so a
    # `.`-named fixture could not exercise it.
    probe_arm_d="${ROOT}/src/check_test_env_arm_d_probe_3475.rs"

    for p in "$probe_violation" "$probe_compliant" "$probe_handrolled" "$probe_comment_only" "$probe_arm_b" "$probe_naked" "$probe_delegate" "$probe_arm_d"; do
        if [[ -e "$p" ]]; then
            echo "ERROR: self-test scratch file already exists: $p" >&2
            echo "(cleanup may have failed in a prior run -- remove manually)" >&2
            exit 2
        fi
    done

    # Case 1: a plain $HOME mutation with NO test_env_lock reference
    # anywhere in the file -- the "nobody serialized it at all" shape
    # (#1998's original defect).
    cat > "$probe_violation" <<'EOF'
// CONTRIVED VIOLATION for scripts/check-test-env-lock.sh --self-test.
// Mutates $HOME with NO reference to the shared env-lock guard
// anywhere in this file -- must be caught. (Deliberately NOT spelling
// the guard's literal identifier in this comment -- the gate's pairing
// check greps the whole file for that token, and this fixture must
// stay a genuine negative.)
#[test]
fn contrived_home_mutation_without_lock() {
    let prev = std::env::var("HOME").ok();
    unsafe {
        std::env::set_var("HOME", "/tmp/contrived");
    }
    match prev {
        Some(p) => unsafe { std::env::set_var("HOME", p) },
        None => unsafe { std::env::remove_var("HOME") },
    }
}
EOF

    # Case 2: a $HOME mutation whose FILE also references the shared
    # guard -- must NOT be flagged (proves the pairing isn't
    # over-widened to reject the compliant shape).
    cat > "$probe_compliant" <<'EOF'
// CONTRIVED COMPLIANT FIXTURE for scripts/check-test-env-lock.sh
// --self-test. Mutates $HOME but the same FILE also references the
// canonical crate::config::test_env_lock() guard -- must NOT be
// flagged.
#[test]
fn contrived_home_mutation_with_lock() {
    let _guard = crate::config::test_env_lock();
    let prev = std::env::var("HOME").ok();
    unsafe {
        std::env::set_var("HOME", "/tmp/contrived");
    }
    match prev {
        Some(p) => unsafe { std::env::set_var("HOME", p) },
        None => unsafe { std::env::remove_var("HOME") },
    }
}
EOF

    # Case 3: a hand-rolled MODULE-LOCAL lock instead of the shared
    # crate-canonical one -- the #1998 -> #2115 -> #2127 recurrent
    # defect class exactly. No reference to test_env_lock anywhere in
    # this file -- must be caught identically to case 1 (the gate does
    # not special-case "some lock exists"; it requires THE canonical
    # one to be reachable, per issue #2146's second bullet).
    cat > "$probe_handrolled" <<'EOF'
// CONTRIVED VIOLATION for scripts/check-test-env-lock.sh --self-test.
// A hand-rolled module-local lock instead of the shared crate-
// canonical guard -- the recurrent #1998/#2115/#2127 defect class. No
// reference to that shared guard's identifier anywhere in this file --
// must be caught exactly like the no-lock-at-all case. (Deliberately
// NOT spelling the guard's literal identifier in this comment -- see
// the sibling violation fixture for why.)
static CONTRIVED_LOCAL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[test]
fn contrived_home_mutation_with_handrolled_lock() {
    let _guard = CONTRIVED_LOCAL_LOCK.lock().unwrap();
    let prev = std::env::var("HOME").ok();
    unsafe {
        std::env::set_var("HOME", "/tmp/contrived");
    }
    match prev {
        Some(p) => unsafe { std::env::set_var("HOME", p) },
        None => unsafe { std::env::remove_var("HOME") },
    }
}
EOF

    # Case 4 (issue #2153a): the shared guard's identifier appears ONLY
    # inside a `//` comment -- never actually called. Pre-fix, the naive
    # whole-file `grep -q test_env_lock` pairing treated ANY textual
    # occurrence (including this comment) as compliant; the
    # comment-stripped pairing check must still catch this.
    cat > "$probe_comment_only" <<'EOF'
// CONTRIVED VIOLATION for scripts/check-test-env-lock.sh --self-test.
// Exercises issue #2153a: this file mentions the canonical guard's
// name only inside a comment -- unlike test_env_lock, this test uses
// its own local mutex, and never actually calls the shared guard.
static CONTRIVED_COMMENT_ONLY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[test]
fn contrived_home_mutation_comment_only_mention() {
    let _guard = CONTRIVED_COMMENT_ONLY_LOCK.lock().unwrap();
    let prev = std::env::var("HOME").ok();
    unsafe {
        std::env::set_var("HOME", "/tmp/contrived_comment_only");
    }
    match prev {
        Some(p) => unsafe { std::env::set_var("HOME", p) },
        None => unsafe { std::env::remove_var("HOME") },
    }
}
EOF

    # Case 5 (issue #2153b): a file that IS file-scope-compliant for its
    # FIRST test (references the canonical guard for real, non-comment,
    # code) but whose SECOND test -- far enough below that it falls
    # outside the module-local-lock adjacency window -- hand-rolls its
    # own local lock for its own $HOME mutation instead of reusing the
    # shared guard. Whole-file pairing alone (arm a) would NOT catch
    # this (the file DOES contain the token); the module-local-lock
    # adjacency arm (b) must catch it independently. The padding block
    # below is deliberately > WINDOW_LINES lines so the first test's
    # token reference cannot be "seen" from the second test's window.
    {
        cat <<'EOF'
// CONTRIVED FIXTURE for scripts/check-test-env-lock.sh --self-test.
// Exercises issue #2153b: file-scope-compliant for its FIRST test (this
// one, which correctly uses the shared guard); a SECOND test far below
// hand-rolls its own module-local lock instead -- the "already-
// compliant file gains a new hand-rolled lock" residual the #2146
// header originally documented as open. Only the module-local-lock
// adjacency arm (b) catches the second test; whole-file pairing (a)
// alone would not, since the file DOES contain the token (right here).
#[test]
fn contrived_compliant_first_test() {
    let _guard = crate::config::test_env_lock();
    let prev = std::env::var("HOME").ok();
    unsafe {
        std::env::set_var("HOME", "/tmp/contrived_b_first");
    }
    match prev {
        Some(p) => unsafe { std::env::set_var("HOME", p) },
        None => unsafe { std::env::remove_var("HOME") },
    }
}
EOF
        for i in $(seq 1 60); do
            printf '// padding line %d -- pushes the second test outside the WINDOW_LINES adjacency window used by arm (b)\n' "$i"
        done
        cat <<'EOF'

static CONTRIVED_LOCAL_LOCK_ARM_B: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[test]
fn contrived_handrolled_second_test() {
    let _guard = CONTRIVED_LOCAL_LOCK_ARM_B.lock().unwrap();
    let prev = std::env::var("HOME").ok();
    unsafe {
        std::env::set_var("HOME", "/tmp/contrived_b_second");
    }
    match prev {
        Some(p) => unsafe { std::env::set_var("HOME", p) },
        None => unsafe { std::env::remove_var("HOME") },
    }
}
EOF
    } > "$probe_arm_b"

    # Case 6 (issue #2163): a file that IS file-scope-compliant for its
    # FIRST test (uses the shared guard for real, non-comment code) whose
    # SECOND test -- far below -- mutates $HOME with NO lock of ANY kind:
    # no local static, no guard call, nothing. This is the EXACT #2163
    # residual. Arm (a) passes (the file contains the token, in the first
    # test). Arm (b) never fires (there is no local lock declaration to be
    # adjacent to). ONLY the fn-scoped arm (c) catches the naked second
    # test. The padding block is deliberately > WINDOW_LINES so the fix
    # cannot lean on adjacency to the first test's token.
    {
        cat <<'EOF'
// CONTRIVED FIXTURE for scripts/check-test-env-lock.sh --self-test.
// Exercises issue #2163: file-scope-compliant for its FIRST test; a
// SECOND test far below mutates $HOME with NO lock at all -- the naked-
// mutation residual that evaded BOTH the whole-file pairing (arm a: the
// file DOES contain the token, right here) AND the module-local-lock
// adjacency arm (b: there is no local lock declaration to be adjacent
// to). Only the fn-scoped arm (c) catches the naked second test.
#[test]
fn contrived_naked_first_test() {
    let _guard = crate::config::test_env_lock();
    let prev = std::env::var("HOME").ok();
    unsafe {
        std::env::set_var("HOME", "/tmp/contrived_naked_first");
    }
    match prev {
        Some(p) => unsafe { std::env::set_var("HOME", p) },
        None => unsafe { std::env::remove_var("HOME") },
    }
}
EOF
        for i in $(seq 1 60); do
            printf '// padding line %d -- pushes the naked second test well past any adjacency window\n' "$i"
        done
        cat <<'EOF'

#[test]
fn contrived_naked_second_test() {
    unsafe {
        std::env::set_var("HOME", "/tmp/contrived_naked_second");
    }
    unsafe {
        std::env::remove_var("HOME");
    }
}
EOF
    } > "$probe_naked"

    # Case 7 (issue #2163, over-widen guard): the config.rs delegate-
    # wrapper carve-out arm (c) must NOT false-positive. A $HOME-mutating
    # test acquires its guard by CALLING a local delegate wrapper
    # (env_var_lock) whose OWN body cites the shared guard, never spelling
    # the literal token in the test fn itself -- exactly the ~40 config.rs
    # sites. Must NOT be flagged: guard_wrapper_names recognises the
    # delegate name as a guard token, so arm (c) treats the test as
    # serialized.
    cat > "$probe_delegate" <<'EOF'
// CONTRIVED COMPLIANT FIXTURE for scripts/check-test-env-lock.sh
// --self-test. Exercises the config.rs delegate-wrapper carve-out arm
// (c) must NOT false-positive: the $HOME-mutating test calls a local
// delegate wrapper (env_var_lock) that transitively cites the shared
// guard -- must NOT be flagged.
fn env_var_lock() -> std::sync::MutexGuard<'static, ()> {
    crate::config::test_env_lock()
}
#[test]
fn contrived_delegate_wrapper_test() {
    let _g = env_var_lock();
    let prev = std::env::var("HOME").ok();
    unsafe {
        std::env::set_var("HOME", "/tmp/contrived_delegate");
    }
    match prev {
        Some(p) => unsafe { std::env::set_var("HOME", p) },
        None => unsafe { std::env::remove_var("HOME") },
    }
}
EOF

    # Case 8 (arm (d), issue #3475): a WHOLLY-NEW src/** file that installs a
    # value into the process-global AI_MEMORY_AGENT_ID. It is not in the
    # ratchet baseline, so arm (d) must flag it as a NEW OFFENDER -- even
    # though it never touches $HOME and is therefore invisible to arms (a)-(c).
    cat > "$probe_arm_d" <<'EOF'
// CONTRIVED VIOLATION for scripts/check-test-env-lock.sh --self-test.
// Installs a value into the process-global AI_MEMORY_AGENT_ID inside the
// lib test binary -- the issue #3475 defect class. Must be caught by arm (d).
#[test]
fn contrived_agent_id_env_install() {
    unsafe {
        std::env::set_var("AI_MEMORY_AGENT_ID", "ai:contrived");
    }
    unsafe {
        std::env::remove_var("AI_MEMORY_AGENT_ID");
    }
}
EOF

    set +e
    gate_output="$("$0" 2>&1)"
    gate_exit=$?
    set -e

    rm -f "$probe_violation" "$probe_compliant" "$probe_handrolled" "$probe_comment_only" "$probe_arm_b" "$probe_naked" "$probe_delegate" "$probe_arm_d"
    printf '%s\n' "$gate_output"

    # PASS requires: non-zero exit, ALL SIX violators reported (no-lock,
    # hand-rolled-lock, comment-only-mention #2153a, the module-local-lock-
    # adjacency #2153b shape, the naked-mutation #2163 shape, and the arm-(d)
    # AI_MEMORY_AGENT_ID install #3475), and BOTH compliant fixtures (the
    # plain compliant one AND the config.rs delegate-wrapper one) NOT
    # reported.
    ok=1
    (( gate_exit != 0 )) || ok=0
    printf '%s' "$gate_output" | grep -q '\.check_home_lock_violation_probe\.rs' || ok=0
    printf '%s' "$gate_output" | grep -q '\.check_home_lock_handrolled_probe\.rs' || ok=0
    printf '%s' "$gate_output" | grep -q '\.check_home_lock_comment_only_probe\.rs' || ok=0
    printf '%s' "$gate_output" | grep -q 'contrived_handrolled_second_test\|\.check_home_lock_arm_b_probe\.rs' || ok=0
    printf '%s' "$gate_output" | grep -q 'contrived_naked_second_test\|\.check_home_lock_naked_probe\.rs' || ok=0
    printf '%s' "$gate_output" | grep -q 'check_test_env_arm_d_probe_3475\.rs' || ok=0
    if printf '%s' "$gate_output" | grep -q '\.check_home_lock_compliant_probe\.rs'; then
        echo "" >&2
        echo "Test-env-lock gate self-test: FAIL (over-widened: the compliant fixture was flagged)" >&2
        exit 1
    fi
    if printf '%s' "$gate_output" | grep -q 'contrived_compliant_first_test'; then
        echo "" >&2
        echo "Test-env-lock gate self-test: FAIL (over-widened: arm (b) flagged the ARM-B probe's own compliant FIRST test, not just the hand-rolled second one)" >&2
        exit 1
    fi
    if printf '%s' "$gate_output" | grep -q 'contrived_naked_first_test'; then
        echo "" >&2
        echo "Test-env-lock gate self-test: FAIL (over-widened: arm (c) flagged the NAKED probe's own compliant FIRST test, not just the naked second one)" >&2
        exit 1
    fi
    if printf '%s' "$gate_output" | grep -q '\.check_home_lock_delegate_probe\.rs\|contrived_delegate_wrapper_test'; then
        echo "" >&2
        echo "Test-env-lock gate self-test: FAIL (over-widened: arm (c) false-positived the config.rs delegate-wrapper carve-out)" >&2
        exit 1
    fi
    if (( ok == 1 )); then
        echo ""
        echo "Test-env-lock gate self-test: PASS (caught all six contrived violations -- five \$HOME shapes plus the #3475 arm (d) AI_MEMORY_AGENT_ID install -- and spared both compliant fixtures; exit=${gate_exit})"
        exit 0
    else
        echo "" >&2
        echo "Test-env-lock gate self-test: FAIL (gate did not catch a contrived violation; exit=${gate_exit})" >&2
        exit 1
    fi
fi

# Main check.
cd "$ROOT"

violations=""
# Arms (a)-(c) record their verdict here rather than exiting immediately, so
# arm (d) (issue #3475) always runs and a single invocation reports BOTH
# defect classes instead of hiding the second behind the first.
home_fail=0

while IFS= read -r -d '' f; do
    rel="${f#"${ROOT}/"}"
    is_allowlisted "$rel" && continue

    home_lines="$(grep -nE "$HOME_PATTERN" "$f" 2>/dev/null || true)"
    [[ -z "$home_lines" ]] && continue

    # Materialize the comment-stripped content ONCE per file and reuse
    # it via here-strings (`<<<`) below, rather than piping a live
    # `strip_line_comments "$f" | grep -q ...` process substitution
    # directly into `grep -q`. `grep -q` exits the instant it finds its
    # first match, which -- under this script's `set -o pipefail` --
    # can SIGPIPE the still-writing `sed` upstream of it; pipefail then
    # reports the PIPELINE's exit status as sed's SIGPIPE failure (a
    # nonzero/signal status) even though grep DID find a real match,
    # false-flagging every $HOME line in an otherwise fully-compliant
    # file (verified: this exact shape false-positived on the live
    # src/reranker.rs / src/cli/rules.rs / src/config.rs / src/
    # embeddings.rs sites during this fix's own authorship -- caught by
    # the mandatory clean-tree false-positive check before merge). A
    # here-string reads from an already-fully-materialized temp
    # file/fd, so `grep -q` reading it early never signals a live
    # writer process.
    stripped_content="$(strip_line_comments "$f")"

    # Arm (a): file-scope pairing over comment-stripped content (issue
    # #2153a). A whole-file miss flags every $HOME line in the file and
    # skips arm (b) for it -- no point double-checking adjacency in a
    # file that has no real reference to the guard at all.
    if ! grep -q "$LOCK_TOKEN" <<< "$stripped_content"; then
        while IFS=: read -r lineno content; do
            [[ -z "$lineno" ]] && continue
            violations+="${rel}:${lineno}:${content}"$'\n'
        done <<< "$home_lines"
        continue
    fi

    # Arm (c): fn-scoped naked-mutation detector (issue #2163). Reached
    # only for arm-(a)-passing files (the file references the guard for
    # real somewhere). Run BEFORE arm (b) because arm (b) `continue`s the
    # loop when the file has no local lock declaration -- the exact shape
    # of the naked-mutation evasion -- so arm (c) must fire first or it
    # would be skipped. The guard-token set is the canonical token plus
    # any delegate-wrapper fn names, so the config.rs `env_var_lock()`
    # delegate tests are NOT false-positived. Lines flagged here that arm
    # (b) also flags are de-duplicated below.
    guard_tokens="$LOCK_TOKEN"
    wrapper_names="$(guard_wrapper_names "$f")"
    [[ -n "$wrapper_names" ]] && guard_tokens="${guard_tokens}"$'\n'"${wrapper_names}"
    mut_csv="$(printf '%s\n' "$home_lines" | cut -d: -f1 | paste -sd, -)"
    while IFS= read -r flagged; do
        [[ -z "$flagged" ]] && continue
        violations+="${rel}:${flagged}"$'\n'
    done < <(naked_home_mutations "$f" "$guard_tokens" "$mut_csv")

    # Arm (b): module-local-lock adjacency (issue #2153b). Only reached
    # for files that PASSED arm (a) -- i.e. the file references the
    # shared guard somewhere for real, but a specific $HOME mutation may
    # still be guarded by its own nearby hand-rolled lock instead.
    # `|| true` on the `grep | cut` pipeline: under `set -o pipefail`
    # (in effect via the script's `set -euo pipefail`), a `grep` that
    # matches nothing exits 1, which -- for a bare `$(pipeline)`
    # assignment -- trips `set -e` and kills the WHOLE script on the
    # very first file with no local-lock declarations (the common
    # case). `|| true` neutralizes that without masking a genuine
    # pattern/regex error, since grep's only failure mode here is "no
    # match" (2>/dev/null already swallows any file-read error) or "no
    # match" propagated through `cut`. Neither `grep -n` here nor `cut`
    # exits early the way `grep -q` does, so no SIGPIPE risk on this
    # pipeline even with a live writer.
    lock_decl_lines="$(grep -nE "$LOCAL_LOCK_PATTERN" "$f" 2>/dev/null | cut -d: -f1 || true)"
    [[ -z "$lock_decl_lines" ]] && continue

    token_lines="$(grep -n "$LOCK_TOKEN" <<< "$stripped_content" | cut -d: -f1 || true)"

    while IFS=: read -r lineno content; do
        [[ -z "$lineno" ]] && continue
        adjacent_lock=0
        for d in $lock_decl_lines; do
            diff=$(( d - lineno )); (( diff < 0 )) && diff=$(( -diff ))
            if (( diff <= WINDOW_LINES )); then
                adjacent_lock=1
                break
            fi
        done
        (( adjacent_lock == 0 )) && continue

        token_nearby=0
        for t in $token_lines; do
            diff=$(( t - lineno )); (( diff < 0 )) && diff=$(( -diff ))
            if (( diff <= WINDOW_LINES )); then
                token_nearby=1
                break
            fi
        done
        if (( token_nearby == 0 )); then
            violations+="${rel}:${lineno}:${content}"$'\n'
        fi
    done <<< "$home_lines"
done < <(
    find "${ROOT}/src" "${ROOT}/tests" -type f -name '*.rs' -print0 2>/dev/null
)

# De-duplicate: a naked-in-a-hand-rolled-lock-fn mutation can be flagged by
# BOTH arm (b) (windowed local-lock adjacency) and arm (c) (fn-scoped), and
# both emit the identical `rel:lineno:content` line -- collapse to one.
violations="$(printf '%s' "$violations" | awk 'NF { if (!seen[$0]++) print }')"

if [[ -n "${violations//[[:space:]]/}" ]]; then
    {
        echo "\$HOME mutation without the shared test_env_lock guard (issue #2146 -- the #1998 -> #2115 -> #2127 recurrent defect class):"
        printf '%s' "$violations" | sed -E 's/^/  /'
        echo ""
        echo "std::env::set_var / remove_var is UNSOUND under concurrent access:"
        echo "two test threads mutating \$HOME at the same time is a real data"
        echo "race, not merely a style nit. Route the guard through the"
        echo "crate-canonical lock so cross-module \$HOME-mutating tests"
        echo "serialize against EACH OTHER, not just within one file:"
        echo ""
        echo "  let _guard = crate::config::test_env_lock();"
        echo ""
        echo "See src/embeddings.rs / src/reranker.rs for the established"
        echo "pattern (save+restore \$HOME under the guard, a SAFETY comment"
        echo "citing serialization by the lock)."
    } >&2
    home_fail=1
fi

if (( home_fail == 0 )); then
    echo "Test-env-lock gate: PASS (every \$HOME-mutating file references the shared test_env_lock guard)"
fi

# ---------------------------------------------------------------------
# Arm (d) -- issue #3475: NO NEW process-global env mutation inside the
# LIB TEST BINARY (src/**/*.rs).
#
# Arms (a)-(c) above police HOW a $HOME mutation is serialized. Arm (d)
# polices WHETHER a src/** test may mutate the process environment at
# all, because #3475 proved the serialization answer does not generalize.
#
# WHAT #3475 WAS. #3356 added two lib tests to src/mcp/mod.rs that
# installed a shape-VALID identity into the process-global
# AI_MEMORY_AGENT_ID (`agent_id_env_set_guard("test-bot")`) under the
# crate-wide `identity::agent_id_env_test_lock()`. That lock serializes
# the MUTATORS against each other -- but `visibility::is_visible_by_fields`
# treats a row with no `metadata.scope` as `private` and therefore
# OWNER-KEYED, and every MCP read dispatch feeds it
# `identity::resolve_read_visibility_caller()`, which reads that same
# variable. So for as long as the guard was held, EVERY CONCURRENT reader
# in the process stopped seeing rows carrying no `metadata.agent_id`:
# `memory_get` masked them as not-found and `memory_get_links` filtered
# their neighbours away. `mcp::tests::handle_get_happy_returns_memory`,
# `handle_get_resolves_by_prefix_and_includes_links` and
# `handle_get_links_returns_outbound_and_inbound` began failing
# nondeterministically on `Check (macos-fed,sqlite)` (run 33662095277).
#
# WHY A LOCK CANNOT BE THE ANSWER HERE. The victims are READERS. To make
# the lock sufficient, every one of the several hundred lib tests that
# transitively resolves identity would have to take it -- unreviewable,
# and one test added tomorrow without it reopens the hole. The sound
# control is PROCESS isolation: a `tests/*.rs` file compiles to its own
# test binary and therefore its own process, so nothing it does to the
# environment can be observed by the `src/**`-embedded `#[cfg(test)]`
# cohort under any scheduling. See tests/mcp_agent_id_env_isolation_3475.rs
# for the pattern (RAII set/unset guard + a binary-local mutex).
#
# HOW THE ARM WORKS (a RATCHET, not a flag day). This repository already
# carried 849 `set_var`/`remove_var` sites across 79 `src/**` files when
# #3475 was fixed; converting all of them is a migration, not a bug fix,
# and a gate that demanded it in one step would simply be switched off.
# So the arm pins a per-file CENSUS baseline
# (scripts/qc-allowlists/test-env-mutation-baseline.txt) and refuses only what
# things WORSE:
#
#   * any src/** file that mutates the environment and is NOT in the
#     baseline (a wholly-new offender -- the common shape),
#   * any baselined file whose total env-mutation count INCREASES,
#   * any baselined file whose AI_MEMORY_AGENT_ID INSTALL count increases
#     (the #3475 shape specifically: `set_var(ENV_AGENT_ID, ..)`,
#     `set_var("AI_MEMORY_AGENT_ID", ..)`, or `agent_id_env_set_guard(..)`
#     -- a `remove_var` / unset guard is NOT an install and is not counted,
#     because clearing the variable can never make a concurrent reader
#     resolve a foreign identity).
#
# Counts going DOWN always pass; the baseline is never auto-relaxed. A
# genuine need to add a site (e.g. a production `set_var` outside any
# test) is a deliberate, reviewed edit: `--update-baseline` rewrites the
# census, and the diff has to be justified in review like any other.
#
# SCOPE / BOUNDS. src/** only -- `tests/**` is exactly the sanctioned
# destination, so gating it would invert the control. Dot-prefixed
# basenames are skipped: a `.foo.rs` can never be a Rust module, so it is
# never compiled into the lib test binary (this is also what keeps the
# arms (a)-(c) self-test fixtures, which are dot-prefixed scratch files,
# from tripping this arm). Line-count based, like every other arm here: a
# `//`-commented mutation counts, which is a deliberate over- rather than
# under-approximation.
# ---------------------------------------------------------------------

# Lines that INSTALL a value into AI_MEMORY_AGENT_ID -- the #3475 shape.
# `remove_var` / the unset guard is deliberately absent (see header).
AGENT_ID_INSTALL_PATTERN='set_var\(([A-Za-z_][A-Za-z0-9_]*::)*ENV_AGENT_ID|set_var\("AI_MEMORY_AGENT_ID"|agent_id_env_set_guard\('

# Any process-global environment mutation.
ENV_MUTATION_PATTERN='(set_var|remove_var)\('

BASELINE_FILE="${ROOT}/scripts/qc-allowlists/test-env-mutation-baseline.txt"

# env_mutation_census
# Emits `<agent_id_installs> <env_mutations> <path>` for every src/**/*.rs
# file with at least one env mutation, sorted by path.
env_mutation_census () {
    while IFS= read -r -d '' f; do
        local base="${f##*/}"
        case "$base" in .*) continue ;; esac
        local e a rel
        e="$(grep -cE "$ENV_MUTATION_PATTERN" "$f" 2>/dev/null || true)"
        a="$(grep -cE "$AGENT_ID_INSTALL_PATTERN" "$f" 2>/dev/null || true)"
        # Skip only when BOTH counters are zero: an identity INSTALL routed
        # through a helper (`agent_id_env_set_guard(..)`) is a #3475 offender
        # even in a file that spells no `set_var`/`remove_var` of its own.
        [[ "${e:-0}" -eq 0 && "${a:-0}" -eq 0 ]] && continue
        rel="${f#"${ROOT}/"}"
        printf '%s %s %s\n' "${a:-0}" "$e" "$rel"
    done < <(find "${ROOT}/src" -type f -name '*.rs' -print0 2>/dev/null) | sort -k3,3
}

if [[ "${1:-}" == "--update-baseline" ]]; then
    {
        echo "# scripts/qc-allowlists/test-env-mutation-baseline.txt -- issue #3475 ratchet baseline."
        echo "#"
        echo "# Format: <AI_MEMORY_AGENT_ID installs> <total env mutations> <path>"
        echo "#"
        echo "# Regenerate with: scripts/check-test-env-lock.sh --update-baseline"
        echo "# A regenerated baseline that RAISES any number is a deliberate,"
        echo "# reviewable widening of the #3475 control -- justify it in review."
        echo "# See the arm (d) header in scripts/check-test-env-lock.sh."
        env_mutation_census
    } > "$BASELINE_FILE"
    echo "Test-env-lock gate: baseline rewritten -> ${BASELINE_FILE#"${ROOT}/"}"
    # Propagate an arms-(a)-(c) failure: rewriting the arm (d) baseline must
    # never launder a $HOME-serialization violation into a green exit.
    exit "$home_fail"
fi

if [[ ! -f "$BASELINE_FILE" ]]; then
    echo "Test-env-lock gate arm (d): missing baseline ${BASELINE_FILE#"${ROOT}/"}" >&2
    echo "(regenerate with: scripts/check-test-env-lock.sh --update-baseline)" >&2
    exit 1
fi

arm_d_report="$(
    env_mutation_census | awk -v baseline="$BASELINE_FILE" '
    BEGIN {
        while ((getline line < baseline) > 0) {
            if (line ~ /^[[:space:]]*(#|$)/) continue
            split(line, F, /[[:space:]]+/)
            known[F[3]] = 1; base_agent[F[3]] = F[1] + 0; base_env[F[3]] = F[2] + 0
        }
        close(baseline)
    }
    {
        agent = $1 + 0; env = $2 + 0; path = $3
        if (!(path in known)) {
            print "  NEW OFFENDER  " path " (env mutations=" env ", AI_MEMORY_AGENT_ID installs=" agent ")"
            next
        }
        if (agent > base_agent[path])
            print "  AI_MEMORY_AGENT_ID installs INCREASED  " path "  " base_agent[path] " -> " agent
        if (env > base_env[path])
            print "  env mutations INCREASED  " path "  " base_env[path] " -> " env
    }
    '
)"

if [[ -n "${arm_d_report//[[:space:]]/}" ]]; then
    {
        echo "New process-global env mutation in the LIB TEST BINARY (issue #3475):"
        printf '%s\n' "$arm_d_report"
        echo ""
        echo "src/**/*.rs compiles into ONE test binary whose tests run in"
        echo "PARALLEL THREADS, so std::env::set_var there is unsound AND"
        echo "globally visible: a test that installs AI_MEMORY_AGENT_ID makes"
        echo "every concurrently-running reader resolve a foreign identity, and"
        echo "an unowned row then reads back as not-found (#3475). Serializing"
        echo "the mutators does not fix it -- the victims are the READERS, and"
        echo "they do not take the lock."
        echo ""
        echo "Put the test in its OWN test binary instead (own process):"
        echo ""
        echo "  tests/<name>.rs   -- see tests/mcp_agent_id_env_isolation_3475.rs"
        echo ""
        echo "If this really is a PRODUCTION mutation (not a test), the baseline"
        echo "bump is a deliberate, reviewed widening:"
        echo ""
        echo "  scripts/check-test-env-lock.sh --update-baseline"
        echo ""
    } >&2
    echo "Test-env-lock gate arm (d): FAIL" >&2
    arm_d_fail=1
else
    arm_d_fail=0
    echo "Test-env-lock gate arm (d): PASS (no src/** file gained env mutation over the #3475 baseline)"
fi

if (( home_fail != 0 || arm_d_fail != 0 )); then
    echo "" >&2
    echo "Test-env-lock gate: FAIL" >&2
    exit 1
fi
