#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# #3669 — temp-directory hygiene gate.
#
# WHY THIS EXISTS: the test suite left hundreds of thousands of entries in
# the gate host's temp root (291 GB at the worst point): directories and
# SQLite main/-wal/-shm files from fixtures that never cleaned up. Three
# code shapes caused it, and this gate blocks each one from coming back:
#
#   R1  `mem::forget(...)` on a guard. In this repo every forget was a
#       tempfile guard kept alive "until the OS reclaims it". The OS does
#       not: the temp root is an ordinary on-disk filesystem. Return the
#       guard with the handle instead, as a `(handle, _guard)` pair.
#       `TempDir::keep()` / `into_path()` are the same leak under another
#       name and are blocked in any file that uses `tempfile`.
#
#   R2  A `static ...: OnceLock<TempDir>`. Rust never runs a static's
#       destructor, so the directory outlives the process. A fixture that
#       really needs one directory per process must go through
#       `ai_memory::test_scratch::process_lifetime_dir(&SLOT, ...)`, which
#       removes it at exit. The gate requires that call for every such
#       static in the same file.
#
#   R3  A literal system temp root (the root `tmp` directory, or its
#       `/var` and macOS `/private` twins) in src/, tests/ or scripts/.
#       The operator forbade the directory outright (2026-09-12); a
#       hardcoded root also defeats `TMPDIR`, so a run pointed elsewhere
#       still writes there. Use the process temp
#       directory (tempfile / `std::env::temp_dir()` / `mktemp`) for real
#       paths and an obviously fake root such as `/example/...` for
#       strings that are only compared.
#
# R3 has exactly one sanctioned site: the shipped default governance rules
# R001-R003 in src/cli/governance_install_defaults.rs, which exist to
# REFUSE writes to those roots. Only the three `pub const` lines that
# define the refused roots may spell them; every other file, including
# the tests of those rules, reads the consts.
#
# Usage:
#   scripts/check-temp-hygiene.sh              gate the working tree
#   scripts/check-temp-hygiene.sh --self-test  plant each violation in a
#                                              scratch copy and prove the
#                                              gate rejects it
#
# Scratch for --self-test lives under <repo>/.local-runs/ (project
# scratch-location rule), never in the system temp directory.

set -euo pipefail
export LC_ALL=C

# The directory name is kept in a variable so this gate never spells a
# temp root itself (it scans scripts/ too).
T="tmp"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The one file allowed to spell a temp root, and the exact line shape
# allowed there.
SANCTIONED_FILE="src/cli/governance_install_defaults.rs"
SANCTIONED_LINE_RE="^pub const R00[123]_REFUSED_ROOT: &str = \"(/${T}|/var/${T}|/private/${T})\";\$"

# A temp root at the START of a path: not preceded by a path character,
# and followed by a separator or the end. Android's `/data/local/...`,
# `tmpfs` and a relative `./...` directory do not match.
TEMP_ROOT_RE="(^|[^A-Za-z0-9_.-])(/private|/var)?/${T}(\$|[^A-Za-z0-9_])"

scan() {
    local root="$1" fail=0 hits

    # R1 — forgetting a guard.
    hits="$(cd "$root" && find src tests benches examples -type f -name '*.rs' 2>/dev/null \
        | sort | xargs grep -nE 'mem::forget\(' 2>/dev/null || true)"
    if [[ -n "$hits" ]]; then
        echo "R1 FAIL: mem::forget keeps a guard alive forever; return it as a (handle, _guard) pair:"
        echo "$hits" | sed 's/^/  /'
        fail=1
    fi
    hits="$(cd "$root" && find src tests -type f -name '*.rs' 2>/dev/null | sort \
        | xargs grep -lE 'tempfile|TempDir|NamedTempFile' 2>/dev/null \
        | xargs grep -nE '\.(keep|into_path)\(\)' 2>/dev/null || true)"
    if [[ -n "$hits" ]]; then
        echo "R1 FAIL: TempDir::keep()/into_path() leaks the directory; hold the guard instead:"
        echo "$hits" | sed 's/^/  /'
        fail=1
    fi

    # R2 — a static TempDir must be registered for exit cleanup.
    local f name
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        while IFS= read -r name; do
            [[ -z "$name" ]] && continue
            if ! grep -qE "process_lifetime_dir\(&${name}\b" "$root/$f"; then
                echo "R2 FAIL: $f: static $name holds a TempDir that is never dropped; pass it to test_scratch::process_lifetime_dir"
                fail=1
            fi
        done < <(grep -oE 'static [A-Z_][A-Z0-9_]*: (std::sync::)?OnceLock<(tempfile::)?TempDir>' "$root/$f" \
            | sed -E 's/^static ([A-Z_][A-Z0-9_]*):.*/\1/')
    done < <(cd "$root" && find src tests -type f -name '*.rs' 2>/dev/null | sort \
        | xargs grep -lE 'OnceLock<(tempfile::)?TempDir>' 2>/dev/null || true)

    # R3 — literal temp roots.
    hits="$(cd "$root" && find src tests scripts -type f 2>/dev/null | sort \
        | xargs grep -nE "$TEMP_ROOT_RE" 2>/dev/null || true)"
    local line file text bad=""
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        file="${line%%:*}"
        text="${line#*:}"; text="${text#*:}"
        if [[ "$file" == "$SANCTIONED_FILE" ]] && [[ "$text" =~ $SANCTIONED_LINE_RE ]]; then
            continue
        fi
        bad+="  $line"$'\n'
    done <<< "$hits"
    if [[ -n "$bad" ]]; then
        echo "R3 FAIL: literal system temp root; use the process temp dir for real paths, /example/... for compared strings:"
        printf '%s' "$bad"
        fail=1
    fi

    return "$fail"
}

self_test() {
    scratch="$REPO_ROOT/.local-runs/check-temp-hygiene-selftest"
    rm -rf "$scratch"
    mkdir -p "$scratch"
    trap 'rm -rf "$scratch"' EXIT

    make_tree() {
        local t="$1"
        rm -rf "$t"
        mkdir -p "$t/src/cli" "$t/tests" "$t/scripts"
        cat > "$t/src/cli/governance_install_defaults.rs" <<EOF
pub const R001_REFUSED_ROOT: &str = "/${T}";
pub const R002_REFUSED_ROOT: &str = "/var/${T}";
pub const R003_REFUSED_ROOT: &str = "/private/${T}";
EOF
        cat > "$t/tests/clean.rs" <<EOF
// Near misses that must pass: android temp, tmpfs, a relative tmp dir,
// a registered process-lifetime dir and a returned guard.
const ANDROID: &str = "/data/local/${T}";
const FS: &str = "tmpfs";
const REL: &str = "./${T}/x";
static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
fn dir() -> &'static std::path::Path {
    ai_memory::test_scratch::process_lifetime_dir(&DIR, || tempfile::TempDir::new().unwrap())
}
fn db() -> (rusqlite::Connection, tempfile::TempDir) { todo!() }
EOF
        printf '#!/usr/bin/env bash\nout="$(mktemp -d)"\n' > "$t/scripts/ok.sh"
    }

    local t="$scratch/tree" ok=1
    make_tree "$t"
    if ! scan "$t" >/dev/null; then
        echo "SELF-TEST FAIL: the clean control tree was rejected:"
        scan "$t" || true
        ok=0
    fi

    # name|file|content|expected rule
    local probes=(
        "forget|tests/p.rs|fn f() { let d = tempfile::TempDir::new().unwrap(); std::mem::forget(d); }|R1 FAIL"
        "keep|tests/p.rs|fn f() -> std::path::PathBuf { tempfile::TempDir::new().unwrap().keep() }|R1 FAIL"
        "static|tests/p.rs|static LEAK: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();|R2 FAIL"
        "root-src|src/p.rs|const P: &str = \"/${T}/x.db\";|R3 FAIL"
        "root-private|tests/p.rs|const P: &str = \"/private/${T}/x\";|R3 FAIL"
        "root-var|tests/p.rs|// a /var/${T} backup would be reaped|R3 FAIL"
        "root-url|tests/p.rs|const U: &str = \"sqlite:///${T}/x.db\";|R3 FAIL"
        "root-script|scripts/p.sh|out=/${T}/report.json|R3 FAIL"
        "sanctioned-elsewhere|tests/p.rs|pub const R001_REFUSED_ROOT: &str = \"/${T}\";|R3 FAIL"
    )
    local p name file content want out
    for p in "${probes[@]}"; do
        IFS='|' read -r name file content want <<< "$p"
        make_tree "$t"
        printf '%s\n' "$content" > "$t/$file"
        if out="$(scan "$t" 2>&1)"; then
            echo "SELF-TEST FAIL: probe '$name' was accepted"
            ok=0
        elif ! grep -q "$want" <<< "$out"; then
            echo "SELF-TEST FAIL: probe '$name' was rejected, but not by $want:"
            echo "$out"
            ok=0
        fi
    done

    # A sanctioned line with any extra content is no longer sanctioned.
    make_tree "$t"
    printf 'pub const R001_REFUSED_ROOT: &str = "/%s"; // plus a /%s note\n' "$T" "$T" \
        > "$t/src/cli/governance_install_defaults.rs"
    if scan "$t" >/dev/null 2>&1; then
        echo "SELF-TEST FAIL: a widened sanctioned line was accepted"
        ok=0
    fi

    if [[ "$ok" -eq 1 ]]; then
        echo "check-temp-hygiene.sh --self-test: PASS (clean control + ${#probes[@]} planted violations + widened-sanction probe)"
        return 0
    fi
    return 1
}

if [[ "${1:-}" == "--self-test" ]]; then
    self_test
    exit $?
fi

if scan "$REPO_ROOT"; then
    echo "check-temp-hygiene.sh: PASS (no forgotten guards, no undropped static TempDir, no literal temp roots)"
    exit 0
fi
echo "check-temp-hygiene.sh: FAIL (#3669)"
exit 1
