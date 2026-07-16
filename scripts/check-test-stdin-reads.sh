#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# v1.0.0 (issue #1989 — full-suite wedge regression guard).
#
# HARD-BLOCK any TEST-reachable acquisition of the process-global
# `std::io::stdin()` handle outside the single sanctioned
# `with_stdin_lines` test helper.
#
# WHY THIS GATE EXISTS (#1989 root cause). The v1.0.0 Gate-1 train hit
# an intermittent full-lib-suite wedge (~1-in-4 locally; a CI watchdog
# kill at 1500s). Root cause (commit c10e55b4, proven live via /proc on
# a wedged PID): the test `cli::shell::tests::
# shell_run_with_eof_stdin_returns_cleanly` called the REPL `run()`
# directly, which blocking-reads the REAL inherited process stdin on the
# assumption it is `/dev/null` (immediate EOF). Under CI runners and
# agent harnesses the test binary inherits a live pipe/socket stdin that
# NEVER yields EOF, so `read_line` parked forever WHILE HOLDING the
# process-global `std::io::Stdin` handle lock — deadlocking the two
# sibling `with_stdin_lines` tests (blocked on that lock, one with fd 0
# already dup2'd to a drained pipe) and wedging the entire parallel lib
# suite.
#
# THE RULE. Any test that must exercise a `run()`/read path over stdin
# MUST route through the sanctioned `with_stdin_lines(...)` helper in
# `src/cli/shell.rs`, which (a) takes the process-global `STDIN_LOCK` so
# the fd-0 mutation is serialised across test threads, (b) dup2s a pipe
# whose write end is CLOSED BEFORE the read (deterministic first-read
# EOF, never a real never-EOF socket), and (c) restores fd 0 panic-safely
# via a Drop guard. A test that instead grabs the real `io::stdin()`
# handle is a suite-wide time bomb: stdin EOF-ness is environment-
# dependent (a GH runner / agent-harness stdin never EOFs), so the read
# blocks forever holding the global lock. Lesson: ai-memory memory
# b02671bf — "grep io::stdin() in test-reachable paths when hunting
# suite wedges."
#
# WHAT IS GATED. The process-global handle acquisition `io::stdin()` /
# `std::io::stdin()` appearing in TEST-reachable code:
#   - every line in a `tests/**/*.rs` integration-test file (wholly test)
#   - lines at or below the first `mod tests {` boundary in any
#     `src/**/*.rs`, `examples/**/*.rs`, or `tools/**/*.rs` file (the
#     in-file test region)
# The CHILD-process stdin pattern (`ChildStdin`, `Stdio::piped()` +
# `child.stdin`) is NOT gated — that writes to a spawned subprocess's
# stdin (RAII-closed), which is the safe pattern the mcp-subprocess tests
# already use. This gate matches only the `io::stdin(` call form, so
# `ChildStdin` type references never trip it.
#
# CARVE-OUT (function-scoped, NOT file-scoped). The single sanctioned
# site is the body of the `fn with_stdin_lines` helper — it acquires the
# handle only to read fd 0 for the dup2 swap under STDIN_LOCK; it never
# blocking-reads the real stdin. The carve-out is the helper FUNCTION,
# resolved by a brace-balanced scan, so an OTHER stdin-reading test in
# the SAME file (e.g. a new `cli::shell::tests` test) is still caught —
# the #1989 wedge test lived in exactly that module, so a whole-file
# carve-out would have left the recurrence site un-gated (#2107).
#
# Production-vs-test boundary heuristic + shell-portability notes mirror
# scripts/check-vendor-literals.sh (the same first-`mod tests {` boundary,
# the same comment-line skip, the same here-string loop to avoid the
# macOS bash 3.2 nested-process-substitution SIGTRAP).
#
# Usage:
#   scripts/check-test-stdin-reads.sh
#     - exit 0 on clean, exit 1 on any violation
#   scripts/check-test-stdin-reads.sh --self-test
#     - injects contrived violations (a plain test read AND a same-file
#       sibling of the helper), verifies the gate catches them, verifies
#       the sanctioned helper line is NOT flagged, then cleans up. Proves
#       the gate is load-bearing AND that the narrow carve-out did not
#       over-widen (pm-v3.2 NO FAIL MISSION closure discipline). Exit 0
#       on PASS.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Process-global stdin handle acquisition. Matches `io::stdin(` and
# `std::io::stdin(` (a leading `std::` is just more `:`), but NOT the
# `ChildStdin` type (no `(` call) nor a `child.stdin` field access.
STDIN_PATTERN='(^|[^A-Za-z0-9_])io::stdin[[:space:]]*\('

# find_test_boundary <file>
# Echoes the line number of the first `mod tests {` (or `pub mod tests {`,
# or `mod test {`); echoes `1` if the file lives under tests/ (wholly a
# test file); echoes `999999999` if no test module is found.
find_test_boundary () {
    local f="$1"
    local rel="${f#"${ROOT}/"}"
    # Integration-test files under tests/ are test code from line 1.
    if [[ "$rel" == tests/* ]]; then
        echo 1
        return 0
    fi
    local line
    line=$(grep -nE '^[[:space:]]*(pub[[:space:]]+)?mod[[:space:]]+tests?[[:space:]]*\{' "$f" 2>/dev/null | head -1 | cut -d: -f1)
    if [[ -z "$line" ]]; then
        echo 999999999
    else
        echo "$line"
    fi
}

# helper_ranges <file>
# Echoes one `start:end` line-range per `fn with_stdin_lines` body in the
# file (brace-balanced), so an io::stdin() match inside the sanctioned
# helper is carved out while an identical call ANYWHERE ELSE in the same
# file is not. The helper's body carries no braces inside string literals,
# so a plain `{`/`}` count is exact here.
helper_ranges () {
    local f="$1"
    awk '
    /(^|[^A-Za-z0-9_])fn[ \t]+with_stdin_lines([^A-Za-z0-9_]|$)/ && !active { active=1; start=NR; depth=0; opened=0 }
    active {
        line=$0
        o=gsub(/\{/,"{",line); depth+=o; if(o>0)opened=1
        c=gsub(/\}/,"}",line); depth-=c
        if(opened && depth<=0){ print start":"NR; active=0 }
    }
    ' "$f" 2>/dev/null
}

# line_in_helper <lineno> <ranges-payload>
# Returns 0 (true) when <lineno> falls within any `start:end` range.
line_in_helper () {
    local lineno="$1"
    local ranges="$2"
    [[ -z "$ranges" ]] && return 1
    local r start end
    while IFS= read -r r; do
        [[ -z "$r" ]] && continue
        start="${r%%:*}"
        end="${r##*:}"
        if (( lineno >= start && lineno <= end )); then
            return 0
        fi
    done <<< "$ranges"
    return 1
}

# scan_test_lines <file>
# Emits "<repo-relative-file>:<lineno>:<content>" for STDIN_PATTERN
# matches in TEST-reachable code (at or below the file's test boundary),
# skipping comment/doc-comment lines and any match inside a sanctioned
# `with_stdin_lines` helper body.
scan_test_lines () {
    local f="$1"
    local boundary
    boundary=$(find_test_boundary "$f")
    local rel="${f#"${ROOT}/"}"
    local matches
    matches="$(grep -En "$STDIN_PATTERN" "$f" 2>/dev/null || true)"
    [[ -z "$matches" ]] && return 0
    local ranges
    ranges="$(helper_ranges "$f")"
    while IFS=: read -r lineno content; do
        [[ -z "$lineno" ]] && continue
        # Only TEST-reachable lines (at or below the boundary).
        if (( lineno < boundary )); then
            continue
        fi
        # Skip the sanctioned helper body.
        if line_in_helper "$lineno" "$ranges"; then
            continue
        fi
        # Skip comments and doc-comment lines.
        local stripped
        stripped=$(printf '%s' "$content" | sed -E 's/^[[:space:]]+//')
        case "$stripped" in
            //*|/\**|\**) continue ;;
        esac
        printf '%s:%s:%s\n' "$rel" "$lineno" "$content"
    done <<< "$matches"
}

# Self-test mode — inject contrived violations, run the gate, confirm it
# catches them (and spares the sanctioned helper line), then clean up.
if [[ "${1:-}" == "--self-test" ]]; then
    echo "Test-stdin gate: self-test mode (contrived violations -> expect HARD-BLOCK -> cleanup)"
    # Case 1: a plain tests/ file that blocking-reads the real stdin in a
    # #[test] (test code from line 1, no `mod tests {` needed).
    probe1="${ROOT}/tests/.stdin_gate_probe.rs"
    # Case 2 (#2107): a file that DEFINES its own `with_stdin_lines`
    # helper (carved out) AND a SIBLING test that reads real stdin — the
    # sibling MUST be caught and the helper's own stdin() line MUST NOT.
    # A tests/ file is test code from line 1, so both functions are in
    # the test region and the function-scoped carve-out is exercised.
    probe2="${ROOT}/tests/.stdin_gate_sibling_probe.rs"
    for p in "$probe1" "$probe2"; do
        if [[ -e "$p" ]]; then
            echo "ERROR: self-test scratch file already exists: $p" >&2
            echo "(cleanup may have failed in a prior run — remove manually)" >&2
            exit 2
        fi
    done
    cat > "$probe1" <<'EOF'
// CONTRIVED VIOLATION for scripts/check-test-stdin-reads.sh --self-test.
// This file is created + deleted by the self-test; if it persists,
// the self-test was killed mid-run — remove it manually.
#[test]
fn contrived_reads_real_stdin() {
    let mut buf = String::new();
    let _ = std::io::stdin().read_line(&mut buf);
}
EOF
    cat > "$probe2" <<'EOF'
// CONTRIVED VIOLATION for scripts/check-test-stdin-reads.sh --self-test.
// Exercises the FUNCTION-scoped carve-out (#2107): the helper's own
// stdin() line must be spared; a sibling test's stdin() must be caught.
fn with_stdin_lines() {
    let _sanctioned = std::io::stdin();
}
#[test]
fn sibling_reads_real_stdin() {
    let mut buf = String::new();
    let _ = std::io::stdin().read_line(&mut buf);
}
EOF
    set +e
    gate_output="$("$0" 2>&1)"
    gate_exit=$?
    set -e
    rm -f "$probe1" "$probe2"
    printf '%s\n' "$gate_output"
    # PASS requires: non-zero exit, BOTH probe violations reported, and
    # the sanctioned helper line (_sanctioned) NOT reported.
    ok=1
    (( gate_exit != 0 )) || ok=0
    printf '%s' "$gate_output" | grep -q '\.stdin_gate_probe\.rs' || ok=0
    printf '%s' "$gate_output" | grep -q 'sibling_reads_real_stdin\|\.stdin_gate_sibling_probe\.rs' || ok=0
    if printf '%s' "$gate_output" | grep -q '_sanctioned'; then
        echo "" >&2
        echo "Test-stdin gate self-test: FAIL (carve-out over-widened: the sanctioned helper line was flagged)" >&2
        exit 1
    fi
    if (( ok == 1 )); then
        echo ""
        echo "Test-stdin gate self-test: PASS (caught both contrived violations, spared the sanctioned helper; exit=${gate_exit})"
        exit 0
    else
        echo "" >&2
        echo "Test-stdin gate self-test: FAIL (gate did not catch a contrived violation; exit=${gate_exit})" >&2
        exit 1
    fi
fi

# Main check.
cd "$ROOT"

stdin_violations=""

while IFS= read -r -d '' f; do
    v=$(scan_test_lines "$f")
    if [[ -n "$v" ]]; then
        stdin_violations+="$v"$'\n'
    fi
done < <(
    find "${ROOT}/src" "${ROOT}/tests" "${ROOT}/examples" "${ROOT}/tools" -type f -name '*.rs' -print0 2>/dev/null
)

if [[ -n "${stdin_violations//[[:space:]]/}" ]]; then
    {
        echo "Test-reachable real-stdin read (issue #1989 full-suite-wedge regression guard):"
        printf '%s' "$stdin_violations" | sed -E 's/^/  /'
        echo ""
        echo "A test that acquires the process-global \`io::stdin()\` handle can"
        echo "block forever holding the global Stdin lock: under CI runners and"
        echo "agent harnesses the inherited stdin is a live pipe/socket that NEVER"
        echo "yields EOF, so a blocking read parks forever and wedges the whole"
        echo "parallel suite (the #1989 root cause, commit c10e55b4)."
        echo ""
        echo "Route the test through the sanctioned helper in src/cli/shell.rs:"
        echo "  with_stdin_lines(\"<input>\", || run(&db))"
        echo "It serialises fd-0 mutation under STDIN_LOCK, feeds a pipe whose"
        echo "write end is closed BEFORE the read (deterministic first-read EOF),"
        echo "and restores fd 0 panic-safely. To drive the pure-EOF path, pass an"
        echo "empty string: \`with_stdin_lines(\"\", || run(&db))\`."
        echo ""
        echo "To write to a spawned SUBPROCESS's stdin instead (the safe pattern),"
        echo "use Stdio::piped() + child.stdin (ChildStdin) — that is NOT gated."
    } >&2
    echo "" >&2
    echo "Test-stdin gate: FAIL" >&2
    exit 1
fi

echo "Test-stdin gate: PASS (no test-reachable process-global io::stdin() reads outside the sanctioned helper)"
