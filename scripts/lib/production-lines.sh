# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
# Shared production-vs-test policy for the hard-block gates (#3623).
#
# #4054: a FILE NAME never proves a file is test-only. The compiler decides
# test-ness from the module DECLARATION (`#[cfg(test)] mod x;`), so a
# production module named `*_tests.rs` / `test_*.rs` / `*_test_*.rs`
# (e.g. src/mcp/dispatch_test_hook.rs, declared with no cfg) must stay
# visible to every gate. A test-looking name only TRIGGERS a declaration
# check; the file is blanked only when every declaration found is itself
# test-gated in the declaring file's production text. No declaration found,
# or any production declaration, keeps the file visible (fail closed).
#
# Bash 3.2 compatible (macOS runners): no associative arrays, no mapfile.

# Recursion guard for a declaring file that is itself test-named.
_PL_DEPTH=0

# _pl_canon <path> — absolute path with the directory resolved physically.
_pl_canon () {
    local d
    d="$(cd "$(dirname "$1")" 2>/dev/null && pwd -P)" || return 1
    printf '%s/%s\n' "$d" "$(basename "$1")"
}

# _pl_declarations <canonical-target> — print `<declaring-file>\t<line>` for
# every recognised declaration of the target:
#   (a) `[#[..] ][pub[(..)]] mod <stem>;` at column 0 of a module parent in the same
#       directory (<dir>/mod.rs, <dir>.rs, <dir>/lib.rs, <dir>/main.rs). A
#       `mod` indented inside an inline module maps to a different path and
#       is ignored, so it can never vouch for this file.
#   (b) `#[path = "..."]` at column 0 whose value, relative to the declaring
#       file's directory, resolves to the target.
#   (c) `include!("...")` at any depth whose value, relative to the including
#       file's directory, resolves to the target.
_pl_declarations () {
    local target="$1" dir base stem cand root hits line file lineno val
    dir="$(dirname "$target")"
    base="$(basename "$target")"
    stem="${base%.rs}"
    for cand in "${dir}/mod.rs" "${dir}.rs" "${dir}/lib.rs" "${dir}/main.rs"; do
        [[ -f "$cand" && "$cand" != "$target" ]] || continue
        hits="$(grep -nE "^(#\[[^]]*\][[:space:]]*)*(pub(\([^)]*\))?[[:space:]]+)?mod[[:space:]]+${stem}[[:space:]]*;" "$cand" || true)"
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            printf '%s\t%s\n' "$cand" "${line%%:*}"
        done <<< "$hits"
    done
    # The declaring files of a crate live under its nearest `src` ancestor.
    root="$dir"
    while [[ "$(basename "$root")" != "src" && "$root" != "/" ]]; do
        root="$(dirname "$root")"
    done
    if [[ "$root" == "/" ]]; then
        root="$dir"
    fi
    hits="$(grep -rnE --include='*.rs' \
        "(^#\[path[[:space:]]*=[[:space:]]*\"|include!\([[:space:]]*\")([^\"]*/)?${stem}\.rs\"" \
        "$root" 2>/dev/null || true)"
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        file="${line%%:*}"
        line="${line#*:}"
        lineno="${line%%:*}"
        line="${line#*:}"
        val="${line#*\"}"
        val="${val%%\"*}"
        [[ "$(_pl_canon "$(dirname "$file")/${val}")" == "$target" ]] || continue
        printf '%s\t%s\n' "$(_pl_canon "$file")" "$lineno"
    done <<< "$hits"
    return 0
}

# _pl_declared_test_only <file> — exit 0 iff the file has at least one
# recognised declaration and EVERY one is blank in its declaring file's
# production text (i.e. sits inside a cfg(test) item, or the declaring file
# is itself test-only). Anything else — including errors — exits 1.
_pl_declared_test_only () {
    local target decls line file lineno production found=0
    (( _PL_DEPTH > 8 )) && return 1
    target="$(_pl_canon "$1")" || return 1
    [[ "$(basename "$target" .rs)" =~ ^[A-Za-z0-9_]+$ ]] || return 1
    decls="$(_pl_declarations "$target")"
    while IFS=$'\t' read -r file lineno; do
        [[ -z "$file" ]] && continue
        found=1
        _PL_DEPTH=$(( _PL_DEPTH + 1 ))
        production="$(production_lines "$file")"
        _PL_DEPTH=$(( _PL_DEPTH - 1 ))
        line="$(printf '%s\n' "$production" | sed -n "${lineno}p")"
        # A surviving declaration line is a production declaration.
        [[ -n "${line//[[:space:]]/}" ]] && return 1
    done <<< "$decls"
    (( found == 1 ))
}

production_lines () {
    local f="$1" stem
    stem="$(basename "$f" .rs)"
    if [[ "$stem" =~ (^|_)tests?(_|$) ]] && _pl_declared_test_only "$f"; then
        return 0
    fi
    "${AWK_BIN:-awk}" -f "${ROOT}/scripts/lib/production-lines.awk" "$f"
}
