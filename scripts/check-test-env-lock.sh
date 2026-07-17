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
# KNOWN RESIDUAL GAP (documented, not silently overclaimed): a NEW test
# fn added to a file that is ALREADY compliant (contains test_env_lock
# somewhere, for its OTHER tests) could theoretically hand-roll its own
# unserialized $HOME mutation without tripping this file-scoped gate.
# Closing that gap needs fn-scoped tracking of every test_env_lock
# DELEGATE wrapper fn (generalizing the config.rs pattern above), which
# is a real but narrower follow-up. Today: (a) every one of the six
# production sites (src/embeddings.rs, src/reranker.rs, src/config.rs,
# src/cli/commands/config.rs, src/cli/rules.rs,
# src/recover/transcript_paths.rs) is correctly gated, and (b) any
# wholesale-NEW file that mutates $HOME without EVER mentioning
# test_env_lock is caught unconditionally -- the class the issue's
# recurrence history (#1998/#2115/#2127) actually exhibited each time.
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
# Usage:
#   scripts/check-test-env-lock.sh
#     - exit 0 on clean, exit 1 on any violation
#   scripts/check-test-env-lock.sh --self-test
#     - injects a violating fixture ($HOME mutation, zero test_env_lock
#       reference anywhere in the file), a compliant fixture (same
#       shape, but the file also references test_env_lock), and a
#       hand-rolled-local-lock fixture (defines its own static
#       Mutex<()> and never references test_env_lock -- exercises the
#       #1998/#2115/#2127 recurrent class directly), verifies the gate
#       catches both violators and spares the compliant fixture, then
#       cleans up. Exit 0 on PASS.

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
# substring appears ANYWHERE in it -- either a direct
# `crate::config::test_env_lock()` call, or (per the config.rs
# delegate pattern documented above) a local wrapper fn whose own body
# cites it.
LOCK_TOKEN='test_env_lock'

# Self-test mode -- inject contrived fixtures, run the gate, confirm it
# catches the violators and spares the compliant fixture, then clean up.
if [[ "${1:-}" == "--self-test" ]]; then
    echo "Test-env-lock gate: self-test mode (contrived violations -> expect HARD-BLOCK -> cleanup)"

    probe_violation="${ROOT}/src/.check_home_lock_violation_probe.rs"
    probe_compliant="${ROOT}/src/.check_home_lock_compliant_probe.rs"
    probe_handrolled="${ROOT}/src/.check_home_lock_handrolled_probe.rs"

    for p in "$probe_violation" "$probe_compliant" "$probe_handrolled"; do
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

    set +e
    gate_output="$("$0" 2>&1)"
    gate_exit=$?
    set -e

    rm -f "$probe_violation" "$probe_compliant" "$probe_handrolled"
    printf '%s\n' "$gate_output"

    # PASS requires: non-zero exit, BOTH violators reported, and the
    # compliant fixture NOT reported.
    ok=1
    (( gate_exit != 0 )) || ok=0
    printf '%s' "$gate_output" | grep -q '\.check_home_lock_violation_probe\.rs' || ok=0
    printf '%s' "$gate_output" | grep -q '\.check_home_lock_handrolled_probe\.rs' || ok=0
    if printf '%s' "$gate_output" | grep -q '\.check_home_lock_compliant_probe\.rs'; then
        echo "" >&2
        echo "Test-env-lock gate self-test: FAIL (over-widened: the compliant fixture was flagged)" >&2
        exit 1
    fi
    if (( ok == 1 )); then
        echo ""
        echo "Test-env-lock gate self-test: PASS (caught both contrived violations, spared the compliant fixture; exit=${gate_exit})"
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

while IFS= read -r -d '' f; do
    rel="${f#"${ROOT}/"}"
    is_allowlisted "$rel" && continue

    home_lines="$(grep -nE "$HOME_PATTERN" "$f" 2>/dev/null || true)"
    [[ -z "$home_lines" ]] && continue

    if ! grep -q "$LOCK_TOKEN" "$f" 2>/dev/null; then
        while IFS=: read -r lineno content; do
            [[ -z "$lineno" ]] && continue
            violations+="${rel}:${lineno}:${content}"$'\n'
        done <<< "$home_lines"
    fi
done < <(
    find "${ROOT}/src" "${ROOT}/tests" -type f -name '*.rs' -print0 2>/dev/null
)

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
    echo "" >&2
    echo "Test-env-lock gate: FAIL" >&2
    exit 1
fi

echo "Test-env-lock gate: PASS (every \$HOME-mutating file references the shared test_env_lock guard)"
