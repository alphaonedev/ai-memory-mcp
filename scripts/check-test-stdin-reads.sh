#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# v1.0.0 (issue #1989 — full-suite wedge regression guard).
#
# HARD-BLOCK any TEST-reachable acquisition of the process-global
# `std::io::stdin()` handle outside the single sanctioned test helper.
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
#     `src/**/*.rs` or `tools/**/*.rs` file (the in-file test region)
# The CHILD-process stdin pattern (`ChildStdin`, `Stdio::piped()` +
# `child.stdin`) is NOT gated — that writes to a spawned subprocess's
# stdin (RAII-closed), which is the safe pattern the mcp-subprocess tests
# already use. This gate matches only the `io::stdin(` call form, so
# `ChildStdin` type references never trip it.
#
# ALLOWLIST. Exactly one carve-out: `src/cli/shell.rs`, home of the
# sanctioned `with_stdin_lines` helper (it acquires the handle only to
# read fd 0 for the dup2 swap under STDIN_LOCK — it never blocking-reads
# the real stdin). The file is the carve-out, mirroring the file-level
# carve-outs in scripts/check-vendor-literals.sh.
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
#     - injects a contrived violation, verifies the gate catches it,
#       removes the violation. Proves the gate is load-bearing
#       (pm-v3.2 NO FAIL MISSION closure discipline). Exit 0 on PASS.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Single file-level carve-out: the sanctioned with_stdin_lines helper.
ALLOWED_FILES=(
    "src/cli/shell.rs"
)

# Process-global stdin handle acquisition. Matches `io::stdin(` and
# `std::io::stdin(` (a leading `std::` is just more `:`), but NOT the
# `ChildStdin` type (no `(` call) nor a `child.stdin` field access.
STDIN_PATTERN='(^|[^A-Za-z0-9_])io::stdin[[:space:]]*\('

# is_allowed_file <repo-root-relative-path>
is_allowed_file () {
    local f="$1"
    local allowed
    for allowed in "${ALLOWED_FILES[@]}"; do
        if [[ "$f" == "$allowed" ]]; then
            return 0
        fi
    done
    return 1
}

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

# scan_test_lines <file>
# Emits "<repo-relative-file>:<lineno>:<content>" for STDIN_PATTERN
# matches in TEST-reachable code (at or below the file's test boundary),
# skipping comment/doc-comment lines.
scan_test_lines () {
    local f="$1"
    local boundary
    boundary=$(find_test_boundary "$f")
    local rel="${f#"${ROOT}/"}"
    local matches
    matches="$(grep -En "$STDIN_PATTERN" "$f" 2>/dev/null || true)"
    [[ -z "$matches" ]] && return 0
    while IFS=: read -r lineno content; do
        [[ -z "$lineno" ]] && continue
        # Only TEST-reachable lines (at or below the boundary).
        if (( lineno < boundary )); then
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

# Self-test mode — inject a contrived violation, run the gate, confirm
# it catches it, then clean up.
if [[ "${1:-}" == "--self-test" ]]; then
    echo "Test-stdin gate: self-test mode (contrived violation -> expect HARD-BLOCK -> cleanup)"
    # A tests/ file is test code from line 1, so a bare io::stdin() there
    # reaches the scanner without needing a `mod tests {` boundary.
    contrived="${ROOT}/tests/.stdin_gate_probe.rs"
    if [[ -e "$contrived" ]]; then
        echo "ERROR: self-test scratch file already exists: $contrived" >&2
        echo "(cleanup may have failed in a prior run — remove manually)" >&2
        exit 2
    fi
    cat > "$contrived" <<'EOF'
// CONTRIVED VIOLATION for scripts/check-test-stdin-reads.sh --self-test.
// This file is created + deleted by the self-test; if it persists,
// the self-test was killed mid-run — remove it manually.
#[test]
fn contrived_reads_real_stdin() {
    let mut buf = String::new();
    let _ = std::io::stdin().read_line(&mut buf);
}
EOF
    set +e
    gate_output="$("$0" 2>&1)"
    gate_exit=$?
    set -e
    rm -f "$contrived"
    printf '%s\n' "$gate_output"
    if (( gate_exit != 0 )) && printf '%s' "$gate_output" | grep -q 'Test-reachable real-stdin read'; then
        echo ""
        echo "Test-stdin gate self-test: PASS (gate caught the contrived violation; exit=${gate_exit})"
        exit 0
    else
        echo "" >&2
        echo "Test-stdin gate self-test: FAIL (gate did not catch the contrived violation; exit=${gate_exit})" >&2
        exit 1
    fi
fi

# Main check.
cd "$ROOT"

stdin_violations=""

while IFS= read -r -d '' f; do
    rel="${f#"${ROOT}/"}"
    if is_allowed_file "$rel"; then
        continue
    fi
    v=$(scan_test_lines "$f")
    if [[ -n "$v" ]]; then
        stdin_violations+="$v"$'\n'
    fi
done < <(
    find "${ROOT}/src" "${ROOT}/tests" "${ROOT}/tools" -type f -name '*.rs' -print0 2>/dev/null
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
