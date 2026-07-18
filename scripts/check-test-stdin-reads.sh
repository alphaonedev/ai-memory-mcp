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
# WHAT IS GATED. The process-global handle acquisition — `io::stdin()`,
# `std::io::stdin()`, a bare `stdin()` call (e.g. after
# `use std::io::stdin;`, which evades a pattern anchored on the
# fully-qualified `io::stdin(` form — issue #2120 finding 1), AND an
# item-renaming `stdin as <alias>` import in EITHER its plain form
# (`use std::io::stdin as input;`, issue #2145) or a GROUPED use-list
# form (`use std::io::{stdin as input, Write};`, issue #2151 — the `{`
# breaks the unbroken `io::stdin` substring #2145's fix anchors on, so
# the grouped spelling evaded it) — appearing in TEST-reachable code:
#   - every line in a `tests/**/*.rs` integration-test file (wholly test)
#   - lines at or below the first `mod tests {` boundary in any
#     `src/**/*.rs`, `examples/**/*.rs`, or `tools/**/*.rs` file (the
#     in-file test region), UNION every item-scoped `#[cfg(test)]` range
#     in the same file (issue #2120 finding 2): a `#[cfg(test)]`-gated
#     fn/item that sits ABOVE the first `mod tests {}`, or a test module
#     under `#[cfg(test)]` with a name other than `tests`/`test` (e.g.
#     `#[cfg(test)] mod repl_smoke { ... }`), is exactly as test-reachable
#     as code inside `mod tests {}` but the pre-fix heuristic anchored
#     SOLELY on `mod tests {` left both classes un-gated. The `#[cfg(test)]`
#     signal is deliberately item-scoped (brace-balanced for a block item,
#     through the terminating `;` for a no-body item), NOT a second
#     from-here-to-EOF cutoff — a single-line `#[cfg(test)]`-gated `use`/
#     `mod foo;` declaration is common well ABOVE a file's real `mod
#     tests {}` (e.g. `src/mcp/mod.rs`), and a from-here-to-EOF cutoff at
#     that line would wrongly treat the PRODUCTION code between it and
#     `mod tests {}` as test-reachable too.
# The CHILD-process stdin pattern (`ChildStdin`, `Stdio::piped()` +
# `child.stdin`, and a `.stdin(` builder call such as
# `Command::new(..).stdin(Stdio::piped())`) is NOT gated — that writes to
# a spawned subprocess's stdin (RAII-closed), which is the safe pattern
# the mcp-subprocess tests already use. The gate's identifier boundary
# excludes a leading `.` (method/field access) so `.stdin(` builder calls
# never trip it, while `io::stdin(` / `std::io::stdin(` / a bare
# `stdin(` (leading `:` or start-of-line) all do.
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
# KNOWN LIMITATION (issue #2152 — threat-model bound, not silently
# mis-parsed). `cfg_test_ranges`' brace-balance scan strips string
# literals PER-LINE (`gsub(/"[^"]*"/, "", counted)`), so it has no
# state for a string that SPANS multiple lines. A multi-line raw
# string (`r#"..."#`) whose body carries a line with more `}` than `{`
# can therefore close an item's range one or more braces early — this
# repo's own `src/` carries live multi-line `r#"`-fixture strings this
# can affect. A bash grep-gate is fundamentally not a Rust lexer/parser
# and a full multi-line-string state machine is deliberately OUT OF
# SCOPE here (fragile, easy to get subtly wrong, and the failure mode
# it would replace is already bounded below). What this gate DOES do:
# whenever the per-line brace count drives `depth` NEGATIVE inside an
# active `#[cfg(test)]` range — the single-line-evaluable subset of the
# truncation class (e.g. a line whose stripped content carries two net
# `}` with no matching `{` on that same line) — it emits a loud WARN to
# stderr naming the file + line, so a truncation in THAT shape is
# visible rather than silently mis-scoping the range. A truncation that
# instead lands EXACTLY at `depth == 0` (the coincidental "looks like a
# normal close" shape) is NOT distinguishable from a legitimate close by
# a brace-count alone and is NOT WARNed on — that residual is real and
# stays open; see self-test probe 10 below for the shape this gate CAN
# catch loud.
#
# Usage:
#   scripts/check-test-stdin-reads.sh
#     - exit 0 on clean, exit 1 on any violation
#   scripts/check-test-stdin-reads.sh --self-test
#     - injects contrived violations (a plain test read, a same-file
#       sibling of the helper, a bare `stdin()` call after
#       `use std::io::stdin;`, a `#[cfg(test)]`-gated fn placed ABOVE
#       `mod tests {}`, a `#[cfg(all(test, unix))]`-gated fn in the same
#       position (#2143), a `#[cfg(test)] mod` whose unbalanced `"}"`
#       string literal would otherwise truncate the range early (#2144),
#       an item-renaming `use std::io::stdin as input;` import (#2145),
#       a fn-pointer `let f = std::io::stdin;` binding (#2145), a
#       GROUPED item-renaming `use std::io::{stdin as input, Write};`
#       import (#2151), and a hard-TAB-indented MULTILINE grouped
#       item-renaming import (#2162 -- the `\tstdin as inp,` line whose
#       leading TAB the pre-fix `[{ ,]` preceding-char class missed)),
#       verifies the gate catches all of them, verifies
#       the sanctioned helper line and a `.stdin(` builder call are NOT
#       flagged, verifies the #2152 negative-brace-balance WARN fires on
#       a multi-line raw string whose body drives the count negative,
#       then cleans up. Proves the gate is load-bearing AND that the
#       narrow carve-out did not over-widen (pm-v3.2 NO FAIL MISSION
#       closure discipline; issue #2120 + #2143/#2144/#2145/#2151/#2152
#       residual-vector hardening). Exit 0 on PASS.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Process-global stdin handle acquisition. Matches `io::stdin(` and
# `std::io::stdin(` (a leading `std::` is just more `:`) AND a bare
# `stdin(` call (issue #2120 finding 1 — a test that does
# `use std::io::stdin;` then calls the imported name unqualified evades
# a pattern anchored on the fully-qualified `io::stdin(` form). The
# excluded-leading-char class `[^A-Za-z0-9_.]` keeps the identifier
# boundary AND excludes a leading `.` so a `.stdin(` builder call (e.g.
# `Command::new(..).stdin(Stdio::piped())`, `cmd.stdin(Stdio::null())`)
# is never matched — that is the child-process pattern (`Command::stdin`
# takes a `Stdio`; it configures a spawned subprocess's stdin, it never
# touches our-process stdin).
STDIN_PATTERN='(^|[^A-Za-z0-9_.])stdin[[:space:]]*\('

# A second, PAREN-LESS signal (issue #2145): STDIN_PATTERN requires the
# call paren adjacent to the `stdin` token, so an item-renaming import
# (`use std::io::stdin as input;` then `input()`) or a fn-pointer binding
# (`let f = std::io::stdin;` then `f()`) — both of which survive
# `cargo fmt --check`, so the CI fmt gate does not normalize them away —
# evade it entirely. Both surviving forms necessarily spell the qualified
# path token `io::stdin` WITHOUT an adjacent `(` (that's what makes them
# evade STDIN_PATTERN); a paren-less `io::stdin` token has essentially no
# legitimate use in test-reachable code (the sanctioned helper calls it
# WITH parens and is carved out anyway), so this pattern flags the
# `use`/`let` acquisition line itself rather than the later call site.
# The excluded trailing class explicitly excludes `(` so a normal
# `io::stdin()` / `std::io::stdin()` call is never double-matched here —
# STDIN_PATTERN alone already covers it.
STDIN_TOKEN_PATTERN='(^|[^A-Za-z0-9_.])io::stdin([^A-Za-z0-9_(]|$)'

# A third signal (issue #2151): STDIN_TOKEN_PATTERN requires the
# literal qualified substring `io::stdin` to appear UNBROKEN, but a
# GROUPED item-renaming import spells it `io::{stdin as <alias>, ...}`
# — the `{` sits between `io::` and `stdin`, so the substring never
# appears and the grouped form evades STDIN_TOKEN_PATTERN even though
# it is the exact same `stdin as` evasion shape #2145 closed for the
# single-import spelling (`use std::io::stdin as input;` IS caught,
# because `io::stdin` survives unbroken there). The SINGLE-LINE grouped
# spelling (`use std::io::{stdin as input, Write};`) survives the CI
# fmt gate unchanged, so anchoring on the `stdin as` token is required.
# (Correction, issue #2162 Finding 2: an earlier note here claimed
# "rustfmt does not split or rejoin a grouped `use` item's contents";
# that is empirically FALSE — rustfmt DOES rejoin a short MULTILINE
# grouped import onto one line. That normalizes toward the caught
# single-line spelling, so it is in the SAFE direction, but the note
# was wrong and is corrected here.) Anchoring directly on the `stdin
# as` token (preceded by start-of-line, `{`, a BLANK — space or TAB —
# or comma, the positions a `use`-item name can occupy) covers BOTH
# the plain and grouped spellings in one pattern; `stdin as` has no
# legitimate non-import use in this codebase (verified against the
# real tree at authorship — a bare `stdin` identifier being `as`-cast
# is not a shape this codebase exhibits).
#
# Issue #2162 Finding 1: the preceding-char class was `[{ ,]` — space
# but NOT TAB — so a hard-TAB-indented multiline grouped alias line
# (`\tstdin as inp,`) evaded the gate. rustfmt rewrites that multiline
# form to the single-line grouping (which the class already caught via
# `{`), so the evasion was fmt-gate-shielded and non-blocking; the
# widened POSIX `[:blank:]` class (space + TAB) now catches the
# tab-indented spelling directly, belt-and-braces, with no new
# false-positive surface (a blank-preceded `stdin as` is still an
# import item name).
STDIN_ALIAS_PATTERN='(^|[{[:blank:],])stdin[[:space:]]+as[[:space:]]'

# find_test_boundary <file>
# Echoes the line number of the first `mod tests {` (or `pub mod tests {`,
# or `mod test {`); echoes `1` if the file lives under tests/ (wholly a
# test file); echoes `999999999` if no test module is found. This is
# ONE of two independent test-reachability signals — see `cfg_test_ranges`
# below for the item-scoped `#[cfg(test)]` signal (issue #2120 finding 2).
# It stays a single from-here-to-EOF cutoff (rather than being folded into
# the ranged scan) because `mod tests { ... }` is conventionally the LAST
# item in a file, so "everything at or below this line" is the correct
# (and simplest) characterization for it specifically.
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

# cfg_test_ranges <file>
# Echoes one `start:end` line-range per test-cfg-attributed ITEM in the
# file (issue #2120 finding 2). Each range starts at the attribute line
# and extends only over THAT item — a brace-balanced scan for a
# block-bodied item (`fn`/`mod`/`impl`/`struct { ... }`), or through the
# first statement-terminating `;` for a no-body item (`mod foo;`,
# `use ...;`, a tuple-struct `struct Foo(..);`). This is deliberately
# ITEM-scoped rather than a single from-here-to-EOF cutoff: a
# `#[cfg(test)]`-gated single-line `use` or module DECLARATION (no body)
# is extremely common ABOVE the file's real `mod tests {}` (e.g.
# `#[cfg(test)] pub(super) mod parity_test_helpers;` in `src/mcp/mod.rs`),
# and a from-here-to-EOF cutoff at that line would wrongly treat every
# production line between it and `mod tests {}` as test-reachable —
# false-positiving on `src/mcp/mod.rs`'s real `io::stdin()` production
# read loop was caught during this fix's repo-wide verification run.
# Stacked attribute lines directly following the trigger attribute (e.g.
# a `#[test]` line before the fn signature) are skipped while scanning
# for the item's opening brace / terminating semicolon.
#
# The trigger admits any cfg predicate containing the bare `test` token —
# not just the literal `#[cfg(test)]` spelling — so `#[cfg(all(test, ...))]`
# and `#[cfg(any(test, ...))]` items are exactly as test-reachable as a
# bare `#[cfg(test)]` item (issue #2143): the repo carries live
# `#[cfg(all(test, feature = "sal"))]` and `#[cfg(all(test, unix))]` sites
# today, and the pre-fix trigger anchored SOLELY on the literal
# `#[cfg(test)]` spelling left both un-gated. `#[cfg(not(test))]` is
# deliberately NOT matched — that predicate selects the opposite of test
# builds, so an item gated by it is never test-reachable.
cfg_test_ranges () {
    local f="$1"
    awk '
    {
        line = $0
        if (!active && line ~ /^[[:space:]]*#\[cfg\((test[,)]|(all|any)\([^)]*[( ,]?test[,)])/) {
            active = 1; start = NR; depth = 0; opened = 0
        }
        if (active) {
            if (opened == 0 && NR != start && line ~ /^[[:space:]]*#\[/) {
                # stacked attribute line before the item itself — skip
            } else {
                # Strip string literals and line comments before
                # brace-counting (issue #2144): an unbalanced brace
                # inside a string literal (e.g. `const X: &str = "}";`,
                # a `write!`/`format!` escape fragment, a partial-JSON
                # fixture) would otherwise close the range early,
                # silently un-gating everything below it in the same
                # item — a fail-SILENT bypass (contrast `helper_ranges`,
                # whose equivalent lexical limitation fails LOUD by
                # narrowing its carve-out instead of widening it). This
                # is a conservative strip — it does not handle escaped
                # quotes — but it removes the entire realistic class.
                counted = line
                gsub(/"[^"]*"/, "", counted)
                sub(/\/\/.*$/, "", counted)
                o = gsub(/\{/, "{", counted); depth += o; if (o > 0) opened = 1
                c = gsub(/\}/, "}", counted); depth -= c
                # Issue #2152 fail-LOUD partial coverage: a per-line
                # brace count that drives depth NEGATIVE (not merely to
                # zero) is a single-line-evaluable symptom of a
                # multi-line string this per-line strip cannot see
                # (e.g. a stripped line carrying two net `}` with no
                # matching `{` on that line). WARN to stderr naming the
                # file+line so the truncation is visible rather than
                # silently mis-scoping the range -- see the "KNOWN
                # LIMITATION (issue #2152)" header comment for the
                # depth==0 residual this cannot distinguish from a
                # legitimate close.
                if (depth < 0) {
                    print "WARN: scripts/check-test-stdin-reads.sh: cfg_test_ranges brace-balance went NEGATIVE at " FILENAME ":" NR " -- likely a multi-line string literal (e.g. r#\"...\"#) whose body carries an unbalanced closing brace this single-line strip cannot see; the enclosing #[cfg(test)] range may be truncated early (issue #2152)." > "/dev/stderr"
                }
                if (opened == 1) {
                    if (depth <= 0) { print start":"NR; active = 0 }
                } else if (line ~ /;[[:space:]]*(\/\/.*)?$/) {
                    print start":"NR; active = 0
                }
            }
        }
    }
    ' "$f"
    # NOTE: unlike the sibling helper_ranges/find_test_boundary
    # functions, this awk invocation's stderr is deliberately NOT
    # redirected to /dev/null -- the issue #2152 negative-depth WARN
    # above is written to stderr and must reach the caller (and, in
    # --self-test mode, the captured `"$0" 2>&1` gate_output) for the
    # fail-LOUD contract to hold.
}

# line_in_ranges <lineno> <ranges-payload>
# Returns 0 (true) when <lineno> falls within any `start:end` range
# (one per line, as emitted by `helper_ranges` / `cfg_test_ranges`).
line_in_ranges () {
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
# Emits "<repo-relative-file>:<lineno>:<content>" for STDIN_PATTERN or
# STDIN_TOKEN_PATTERN matches in TEST-reachable code — at or below the
# file's `mod tests {}` boundary, OR inside any item-scoped test-cfg
# range (issue #2120 finding 2; widened by issue #2143) — skipping
# comment/doc-comment lines and any match inside a sanctioned
# `with_stdin_lines` helper body.
scan_test_lines () {
    local f="$1"
    local boundary
    boundary=$(find_test_boundary "$f")
    local rel="${f#"${ROOT}/"}"
    local matches
    matches="$(
        {
            grep -En "$STDIN_PATTERN" "$f" 2>/dev/null || true
            grep -En "$STDIN_TOKEN_PATTERN" "$f" 2>/dev/null || true
            grep -En "$STDIN_ALIAS_PATTERN" "$f" 2>/dev/null || true
        } | sort -t: -k1,1n -u
    )"
    [[ -z "$matches" ]] && return 0
    local cfg_ranges
    cfg_ranges="$(cfg_test_ranges "$f")"
    local ranges
    ranges="$(helper_ranges "$f")"
    while IFS=: read -r lineno content; do
        [[ -z "$lineno" ]] && continue
        # TEST-reachable lines: at/below the `mod tests {}` boundary, OR
        # inside an item-scoped `#[cfg(test)]` range (issue #2120 finding
        # 2). Neither signal alone is sufficient — see the comments on
        # `find_test_boundary` / `cfg_test_ranges` above.
        if (( lineno < boundary )) && ! line_in_ranges "$lineno" "$cfg_ranges"; then
            continue
        fi
        # Skip the sanctioned helper body.
        if line_in_ranges "$lineno" "$ranges"; then
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
    # This probe ALSO carries a `.stdin(` builder call (a spawned
    # subprocess's stdin config) to prove the #2120-broadened pattern
    # still spares it.
    probe2="${ROOT}/tests/.stdin_gate_sibling_probe.rs"
    # Case 3 (#2120 finding 1): a bare `stdin()` call after
    # `use std::io::stdin;` — must be caught even though it never
    # spells `io::stdin(`.
    probe3="${ROOT}/tests/.stdin_gate_bare_import_probe.rs"
    # Case 4 (#2120 finding 2): a `#[cfg(test)]`-gated fn placed ABOVE
    # the file's first `mod tests {` — must be caught even though it
    # sits before the pre-fix boundary marker. Lives under src/ (not
    # tests/, which is test-code-from-line-1 unconditionally) so the
    # in-file boundary heuristic is actually exercised; it is not
    # `mod`-included anywhere so cargo never compiles it.
    probe4="${ROOT}/src/.stdin_gate_cfg_boundary_probe.rs"
    # Case 5 (#2143): a `#[cfg(all(test, unix))]`-gated fn placed ABOVE
    # the file's first `mod tests {` — the composed-predicate sibling of
    # probe4's bare `#[cfg(test)]`; must be caught by the widened
    # cfg_test_ranges trigger. Lives under src/ for the same reason as
    # probe4 (exercises the in-file boundary heuristic; never
    # `mod`-included so cargo never compiles it).
    probe5="${ROOT}/src/.stdin_gate_cfg_all_probe.rs"
    # Case 6 (#2144): a `#[cfg(test)] mod` whose body contains an
    # unbalanced-brace string literal (`"}"`) ABOVE the stdin read — the
    # naive brace-count in cfg_test_ranges would close the range at that
    # string, silently un-gating the read below it. No `mod tests {}` in
    # the file, so the item-scoped #[cfg(test)] range is the ONLY signal
    # that can catch it.
    probe6="${ROOT}/src/.stdin_gate_string_brace_probe.rs"
    # Case 7 (#2145 form 1): an item-renaming import
    # (`use std::io::stdin as input;`) — the paren-anchored STDIN_PATTERN
    # never sees `input(`, so only the paren-less STDIN_TOKEN_PATTERN over
    # the qualified `io::stdin` token catches the import line itself.
    probe7="${ROOT}/tests/.stdin_gate_alias_import_probe.rs"
    # Case 8 (#2145 form 2): a fn-pointer binding (`let f =
    # std::io::stdin;`) — same evasion shape as case 7, a paren-less
    # `io::stdin` token with no adjacent call.
    probe8="${ROOT}/tests/.stdin_gate_fn_pointer_probe.rs"
    # Case 9 (#2151): a GROUPED item-renaming import
    # (`use std::io::{stdin as input, Write};`) -- the `{` breaks the
    # unbroken `io::stdin` substring STDIN_TOKEN_PATTERN anchors on, so
    # only the new STDIN_ALIAS_PATTERN (anchored on the `stdin as`
    # token itself) catches the import line.
    probe9="${ROOT}/tests/.stdin_gate_grouped_alias_import_probe.rs"
    # Case 10 (#2152): a multi-line raw string whose body drives the
    # cfg_test_ranges brace-balance NEGATIVE (two net `}` on one
    # stripped line) -- proves the fail-LOUD WARN path fires. This
    # probe's own stdin read is NOT asserted caught (the range IS
    # truncated early, same as the documented #2152 residual) -- only
    # the WARN text is asserted, which is the honest scope of this fix.
    probe10="${ROOT}/src/.stdin_gate_multiline_negative_depth_probe.rs"
    # Case 11 (#2162): a hard-TAB-indented MULTILINE grouped item-renaming
    # import. The pre-fix STDIN_ALIAS_PATTERN preceding-char class `[{ ,]`
    # covered space but NOT tab, so `\tstdin as inp,` on its own line
    # evaded the gate. Lives under tests/ (test-code-from-line-1) so the
    # import line is unconditionally test-reachable.
    probe11="${ROOT}/tests/.stdin_gate_tab_grouped_alias_import_probe.rs"
    for p in "$probe1" "$probe2" "$probe3" "$probe4" "$probe5" "$probe6" "$probe7" "$probe8" "$probe9" "$probe10" "$probe11"; do
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
#[test]
fn benign_child_stdin_builder() {
    let _cmd_ok_not_flagged = std::process::Command::new("true")
        .stdin(std::process::Stdio::piped());
}
EOF
    cat > "$probe3" <<'EOF'
// CONTRIVED VIOLATION for scripts/check-test-stdin-reads.sh --self-test.
// Exercises issue #2120 finding 1: a bare `stdin()` call after
// `use std::io::stdin;` evades a pattern anchored on `io::stdin(`.
use std::io::stdin;
#[test]
fn contrived_bare_stdin_after_import() {
    let mut buf = String::new();
    let _ = stdin().read_line(&mut buf);
}
EOF
    cat > "$probe4" <<'EOF'
// CONTRIVED VIOLATION for scripts/check-test-stdin-reads.sh --self-test.
// Exercises issue #2120 finding 2: a #[cfg(test)]-gated fn placed ABOVE
// the file's first `mod tests {` must still be test-reachable.
#[cfg(test)]
fn contrived_cfg_gated_reads_stdin() {
    let mut buf = String::new();
    let _ = std::io::stdin().read_line(&mut buf);
}

mod tests {
    // Padding so `mod tests {` is not the first test marker in the
    // file — the fn above it must still be caught via the earlier
    // `#[cfg(test)]` attribute line.
}
EOF
    cat > "$probe5" <<'EOF'
// CONTRIVED VIOLATION for scripts/check-test-stdin-reads.sh --self-test.
// Exercises issue #2143: a #[cfg(all(test, unix))]-gated fn placed ABOVE
// the file's first `mod tests {` must be exactly as test-reachable as a
// bare #[cfg(test)] item.
#[cfg(all(test, unix))]
fn contrived_cfg_all_reads_stdin() {
    let mut buf = String::new();
    let _ = std::io::stdin().read_line(&mut buf);
}

mod tests {
    // Padding so `mod tests {` is not the first test marker in the
    // file — the fn above it must still be caught via the earlier
    // `#[cfg(all(test, unix))]` attribute line.
}
EOF
    cat > "$probe6" <<'EOF'
// CONTRIVED VIOLATION for scripts/check-test-stdin-reads.sh --self-test.
// Exercises issue #2144: an unbalanced-brace string literal ("}") inside
// a #[cfg(test)] mod must NOT silently truncate the item's cfg_test_ranges
// range before the stdin read below it.
#[cfg(test)]
mod sneaky {
    const X: &str = "}";
    fn contrived_string_brace_reads_stdin() {
        let mut buf = String::new();
        let _ = std::io::stdin().read_line(&mut buf);
    }
}
EOF
    cat > "$probe7" <<'EOF'
// CONTRIVED VIOLATION for scripts/check-test-stdin-reads.sh --self-test.
// Exercises issue #2145 form 1: an item-renaming import survives
// `cargo fmt --check`, so `use std::io::stdin as input;` then `input()`
// evades the paren-anchored STDIN_PATTERN entirely.
use std::io::stdin as input;
#[test]
fn contrived_alias_import_reads_stdin() {
    let mut buf = String::new();
    let _ = input().read_line(&mut buf);
}
EOF
    cat > "$probe8" <<'EOF'
// CONTRIVED VIOLATION for scripts/check-test-stdin-reads.sh --self-test.
// Exercises issue #2145 form 2: a fn-pointer binding survives
// `cargo fmt --check`, so `let f = std::io::stdin;` then `f()` evades the
// paren-anchored STDIN_PATTERN entirely.
#[test]
fn contrived_fn_pointer_reads_stdin() {
    let f = std::io::stdin;
    let mut buf = String::new();
    let _ = f().read_line(&mut buf);
}
EOF
    cat > "$probe9" <<'EOF'
// CONTRIVED VIOLATION for scripts/check-test-stdin-reads.sh --self-test.
// Exercises issue #2151: a GROUPED item-renaming import survives
// `cargo fmt --check` (rustfmt does not split/rejoin a grouped `use`
// item), so `use std::io::{stdin as input, Write};` then `input()`
// evades STDIN_TOKEN_PATTERN entirely (the `{` breaks the unbroken
// `io::stdin` substring it anchors on) even though the single-import
// sibling form (#2145) is already caught.
use std::io::{stdin as input, Write};
#[test]
fn contrived_grouped_alias_import_reads_stdin() {
    let mut buf = String::new();
    let _ = input().read_line(&mut buf);
    let _ = Write::flush(&mut std::io::stdout());
}
EOF
    cat > "$probe10" <<'EOF'
// CONTRIVED VIOLATION for scripts/check-test-stdin-reads.sh --self-test.
// Exercises issue #2152's fail-LOUD path: a multi-line raw string whose
// body carries a line with two net closing-brace characters drives the
// cfg_test_ranges brace-balance NEGATIVE (not merely to zero) inside a
// #[cfg(test)] range -- the single-line-evaluable subset of the
// per-line-string-strip truncation class this gate can cheaply detect
// and WARN on (see script header "KNOWN LIMITATION (issue #2152)"). A
// full multi-line-string parser remains explicitly out of scope for
// this bash gate; the stdin read below is NOT asserted caught by this
// probe (the range IS truncated early, same as the documented residual)
// -- only the loud WARN is asserted.
#[cfg(test)]
mod sneaky_ml_negative_probe {
    const K: &str = r#"
    }}
    "#;
    fn contrived_multiline_negative_depth_reads_stdin() {
        let mut buf = String::new();
        let _ = std::io::stdin().read_line(&mut buf);
    }
}
EOF
    # Built with printf so the indent is a genuine hard TAB byte (a
    # `<<'EOF'` heredoc's leading whitespace could be normalized by an
    # editor / formatter and silently defeat the probe).
    {
        printf '%s\n' "// CONTRIVED VIOLATION for scripts/check-test-stdin-reads.sh --self-test."
        printf '%s\n' "// Exercises issue #2162: a hard-TAB-indented MULTILINE grouped"
        printf '%s\n' "// item-renaming import evades the space-only STDIN_ALIAS_PATTERN"
        printf '%s\n' "// preceding-char class -- the leading TAB before \`stdin as\` is not"
        printf '%s\n' "// \`{\`, space, or comma. rustfmt would rejoin this to the caught"
        printf '%s\n' "// single-line spelling, so the evasion is fmt-gate-shielded; the"
        printf '%s\n' "// widened \`[{[:blank:],]\` class catches it directly regardless."
        printf '%s\n' "use std::io::{"
        printf '\t%s\n' "stdin as inp,"
        printf '%s\n' "    Write,"
        printf '%s\n' "};"
        printf '%s\n' "#[test]"
        printf '%s\n' "fn contrived_tab_grouped_alias_import_reads_stdin() {"
        printf '%s\n' "    let mut buf = String::new();"
        printf '%s\n' "    let _ = inp().read_line(&mut buf);"
        printf '%s\n' "    let _ = Write::flush(&mut std::io::stdout());"
        printf '%s\n' "}"
    } > "$probe11"
    set +e
    gate_output="$("$0" 2>&1)"
    gate_exit=$?
    set -e
    rm -f "$probe1" "$probe2" "$probe3" "$probe4" "$probe5" "$probe6" "$probe7" "$probe8" "$probe9" "$probe10" "$probe11"
    printf '%s\n' "$gate_output"
    # PASS requires: non-zero exit, TEN probe violations reported (the
    # #2152 negative-depth probe is asserted via its loud WARN instead --
    # its stdin read is deliberately NOT expected caught, see the probe10
    # comment above), and the sanctioned helper line + the benign builder
    # call NOT reported.
    ok=1
    (( gate_exit != 0 )) || ok=0
    printf '%s' "$gate_output" | grep -q '\.stdin_gate_probe\.rs' || ok=0
    printf '%s' "$gate_output" | grep -q 'sibling_reads_real_stdin\|\.stdin_gate_sibling_probe\.rs' || ok=0
    printf '%s' "$gate_output" | grep -q 'contrived_bare_stdin_after_import\|\.stdin_gate_bare_import_probe\.rs' || ok=0
    printf '%s' "$gate_output" | grep -q 'contrived_cfg_gated_reads_stdin\|\.stdin_gate_cfg_boundary_probe\.rs' || ok=0
    printf '%s' "$gate_output" | grep -q 'contrived_cfg_all_reads_stdin\|\.stdin_gate_cfg_all_probe\.rs' || ok=0
    printf '%s' "$gate_output" | grep -q 'contrived_string_brace_reads_stdin\|\.stdin_gate_string_brace_probe\.rs' || ok=0
    printf '%s' "$gate_output" | grep -q 'use std::io::stdin as input\|\.stdin_gate_alias_import_probe\.rs' || ok=0
    printf '%s' "$gate_output" | grep -q 'let f = std::io::stdin\|\.stdin_gate_fn_pointer_probe\.rs' || ok=0
    printf '%s' "$gate_output" | grep -q 'stdin as input\|\.stdin_gate_grouped_alias_import_probe\.rs' || ok=0
    printf '%s' "$gate_output" | grep -q '\.stdin_gate_tab_grouped_alias_import_probe\.rs' || ok=0
    printf '%s' "$gate_output" | grep -q 'brace-balance went NEGATIVE.*stdin_gate_multiline_negative_depth_probe' || ok=0
    if printf '%s' "$gate_output" | grep -q '_sanctioned'; then
        echo "" >&2
        echo "Test-stdin gate self-test: FAIL (carve-out over-widened: the sanctioned helper line was flagged)" >&2
        exit 1
    fi
    if printf '%s' "$gate_output" | grep -q 'benign_child_stdin_builder\|cmd_ok_not_flagged'; then
        echo "" >&2
        echo "Test-stdin gate self-test: FAIL (over-widened: a .stdin( child-process builder call was flagged)" >&2
        exit 1
    fi
    if (( ok == 1 )); then
        echo ""
        echo "Test-stdin gate self-test: PASS (caught ten contrived violations + fired the #2152 negative-depth WARN, spared the sanctioned helper + benign builder call; exit=${gate_exit})"
        exit 0
    else
        echo "" >&2
        echo "Test-stdin gate self-test: FAIL (gate did not catch a contrived violation or fire the #2152 WARN; exit=${gate_exit})" >&2
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
