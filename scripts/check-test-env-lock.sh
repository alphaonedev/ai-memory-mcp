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
# its own unserialized $HOME mutation nearby. Two arms close both:
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
# Every one of the six production sites (src/embeddings.rs,
# src/reranker.rs, src/config.rs, src/cli/commands/config.rs,
# src/cli/rules.rs, src/recover/transcript_paths.rs) is correctly gated
# under both arms, and any wholesale-NEW file that mutates $HOME without
# EVER mentioning test_env_lock in real code is caught unconditionally --
# the class the issue's recurrence history (#1998/#2115/#2127) actually
# exhibited each time.
#
# NARROWER RESIDUAL (documented, not silently overclaimed): a hand-
# rolled local lock declared MORE than WINDOW_LINES lines from the
# $HOME mutation it guards (e.g. at the top of a very large file, used
# far below) would still evade arm (b) while the file stays file-scope
# "compliant" if it also references test_env_lock elsewhere. This is a
# real but narrower gap than the one #2153 closes; a fn/block-scoped
# structural scan (generalizing the config.rs delegate-wrapper pattern)
# is the follow-up if this shape is ever observed in practice.
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
#     - injects: a violating fixture ($HOME mutation, zero test_env_lock
#       reference anywhere in the file), a compliant fixture (same
#       shape, but the file also references test_env_lock), a
#       hand-rolled-local-lock fixture (defines its own static
#       Mutex<()> and never references test_env_lock -- exercises the
#       #1998/#2115/#2127 recurrent class directly), a comment-only-
#       mention fixture (issue #2153a -- the token appears ONLY inside
#       a `//` comment), and a module-local-lock-adjacency fixture
#       (issue #2153b -- file-scope-compliant for its FIRST test, but a
#       SECOND test >WINDOW_LINES away hand-rolls its own local lock for
#       its own $HOME mutation); verifies the gate catches all four
#       violators and spares the compliant fixture, then cleans up.
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

# Self-test mode -- inject contrived fixtures, run the gate, confirm it
# catches the violators and spares the compliant fixture, then clean up.
if [[ "${1:-}" == "--self-test" ]]; then
    echo "Test-env-lock gate: self-test mode (contrived violations -> expect HARD-BLOCK -> cleanup)"

    probe_violation="${ROOT}/src/.check_home_lock_violation_probe.rs"
    probe_compliant="${ROOT}/src/.check_home_lock_compliant_probe.rs"
    probe_handrolled="${ROOT}/src/.check_home_lock_handrolled_probe.rs"
    probe_comment_only="${ROOT}/src/.check_home_lock_comment_only_probe.rs"
    probe_arm_b="${ROOT}/src/.check_home_lock_arm_b_probe.rs"

    for p in "$probe_violation" "$probe_compliant" "$probe_handrolled" "$probe_comment_only" "$probe_arm_b"; do
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

    set +e
    gate_output="$("$0" 2>&1)"
    gate_exit=$?
    set -e

    rm -f "$probe_violation" "$probe_compliant" "$probe_handrolled" "$probe_comment_only" "$probe_arm_b"
    printf '%s\n' "$gate_output"

    # PASS requires: non-zero exit, ALL FOUR violators reported (no-lock,
    # hand-rolled-lock, comment-only-mention #2153a, and the module-
    # local-lock-adjacency #2153b shape), and the compliant fixture NOT
    # reported.
    ok=1
    (( gate_exit != 0 )) || ok=0
    printf '%s' "$gate_output" | grep -q '\.check_home_lock_violation_probe\.rs' || ok=0
    printf '%s' "$gate_output" | grep -q '\.check_home_lock_handrolled_probe\.rs' || ok=0
    printf '%s' "$gate_output" | grep -q '\.check_home_lock_comment_only_probe\.rs' || ok=0
    printf '%s' "$gate_output" | grep -q 'contrived_handrolled_second_test\|\.check_home_lock_arm_b_probe\.rs' || ok=0
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
    if (( ok == 1 )); then
        echo ""
        echo "Test-env-lock gate self-test: PASS (caught all four contrived violations, spared the compliant fixture; exit=${gate_exit})"
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
