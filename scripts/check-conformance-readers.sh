#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Non-Rust conformance-reader proof gate (#2452).
#
# CLASS: "a control that reports success when it did nothing" -- the same
# class as #2444 (a valid checksum written over an empty file), #2449 (an
# installer that failed open on a missing checksum) and #2443 (declared
# branch-protection contexts that cannot be enforced).
#
# WHAT WAS BROKEN. `docs/spec/PORTABILITY-V2.md` and ROADMAP Gate 1 require
# ">=2 independent non-Rust reference reader implementations that VERIFY
# (not merely parse) the signed-record family against the CC0 conformance
# corpus" -- the dark-age / Rosetta property, and the strongest portability
# claim the project makes. It was verified by two tests in
# `tests/conformance_readers.rs` that BOTH returned early with a `SKIP:`
# note when `python3` / `node` were absent, which libtest scores as `ok`.
# No workflow referenced the suite at all, so no environment was KNOWN to
# carry the interpreters. Measured on the pre-fix harness with an
# interpreter-free PATH: `test result: ok. 2 passed` -- and libtest
# captured the SKIP notes, so even the warning was invisible. A Gate-1
# freeze-critical item marked DISCHARGED was proven by a test that could
# no-op to green.
#
# The "2" was never asserted either: with python3 present and node absent,
# the mandated two readers silently became one, still green.
#
# THIS GATE. Three modes, none of which can skip:
#
#   scripts/check-conformance-readers.sh
#     GATE mode (the CI proof). Needs no cargo build.
#       G0 the escape hatch + the golden-regen toggle are UNSET in this
#          process (a runtime check -- a static workflow grep cannot see an
#          org-level or repo-level GitHub `vars`/`env` injection).
#       G1 the corpus, the manifest and every declared reader exist.
#       G2 an interpreter is RESOLVED for every declared reader. ABSENT IS
#          A VIOLATION, never a skip. This is the whole point.
#       G3 each reader RUNS over the corpus; output is captured to a file
#          (never a pipe, so no exit status is laundered).
#       G4 exit 0, no `FAIL ` line, no `(FAILURES)`, `N/N items passed`
#          with N at or above the pinned floor, and every load-bearing
#          verdict line present BY NAME -- a stub that exits 0 printing
#          nothing must not score as a verification.
#       G5 per-reader honesty pins: python must label its stdlib signature
#          limitation `PASS (partial)`; node must emit NO partial.
#       G6 the COUNT obligation: >= REQUIRED_READERS readers structurally
#          verified, and >= MIN_SIGNATURE_VERIFYING signature-verified.
#       G7 `tests/conformance_readers.rs` still carries the fail-closed
#          region, its abort sites, and no silent-skip phrase; and is still
#          crate-dependency-free (the R-203 machinery below depends on it).
#       G8 at least one workflow actually references this gate.
#       G9 no workflow sets the escape hatch or the golden-regen toggle.
#     Exit 0 clean, exit 1 on any violation.
#
#   scripts/check-conformance-readers.sh --self-test
#     BEHAVIOURAL mode (the load-bearing evidence). PLANTS failures and
#     proves the gate rejects each, asserting the SPECIFIC violation token
#     rather than merely a non-zero exit -- the #2470 lane's harness twice
#     "passed" for the wrong reason (once on exit 127 because the binary
#     never ran, once because a runner env var made the subject bail before
#     reaching the checked code), and that is the illusion this whole issue
#     is about. An unmutated CONTROL runs first, or no plant proves
#     anything. Every corpus plant mutates a COPY under `.local-runs/`; the
#     durable `conformance/` tree is NEVER written to.
#
#   scripts/check-conformance-readers.sh --r203 <git-ref>
#     R-203 evidence mode. Compiles the HISTORICAL
#     `tests/conformance_readers.rs` from a git ref STANDALONE with
#     `rustc --test` (the file is deliberately crate-dependency-free), runs
#     it against a PATH with no interpreters, and asserts it reports
#     `2 passed` -- reproducing the silent pass on the pre-fix revision.
#     The compile is asserted separately from the run so a compile error
#     can never be misread as "the test failed".
#
# Scratch lives under `.local-runs/` per the project hard rule -- never
# `/tmp`, `/var/tmp`, or any tmpfs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS_ROOT="${REPO_ROOT}/conformance"
MANIFEST="${CORPUS_ROOT}/manifest.json"
HARNESS="${REPO_ROOT}/tests/conformance_readers.rs"
WORKFLOW_DIR="${REPO_ROOT}/.github/workflows"
SCRATCH_ROOT="${REPO_ROOT}/.local-runs/check-conformance-readers"

# --- SSOT: the declared non-Rust reader inventory -------------------------
# label | candidate interpreters | version marker | script | partial-policy
# partial-policy: `partial-required` (stdlib, cannot do Ed25519 -- must say
# so explicitly) or `no-partial` (fully verifies signatures).
READER_SPECS=(
    "python|python3 python|Python 3|readers/reader.py|partial-required"
    "node|node nodejs|v|readers/reader.mjs|no-partial"
)

# ROADMAP 11.6, NOT relaxed: readers that must structurally verify.
REQUIRED_READERS=2

# Readers that must additionally check the Ed25519 SIGNATURES.
#
# HONEST PIN, NOT THE SPEC NUMBER. PORTABILITY-V2 requires that a
# conforming reader "check the signatures", i.e. this should be 2. Today it
# is 1: only `node` has an Ed25519 primitive in its standard library, and
# the Python reader vendors no crypto by policy, so it reports its
# signature verdicts as explicit `PASS (partial)`. Raising this floor needs
# a SECOND signature-verifying non-Rust reader (or a sanctioned optional
# dependency for the Python arm) -- a spec-level decision, tracked
# separately. Pinning it here means the shortfall is MEASURED and cannot
# silently get worse; it is deliberately not papered over as "2 readers
# verify the signed family".
MIN_SIGNATURE_VERIFYING=1

# Floor on the number of corpus items a reader must report passing, and on
# the record files on disk. Cross-checked against the FILESYSTEM as well as
# the manifest, because the manifest is the reader's own answer key: an
# emptied manifest would otherwise yield a happy `1/1 items passed`.
MIN_CORPUS_ITEMS=18
MIN_RECORD_FILES=27

# Load-bearing corpus items. A reader that exits 0 without reporting a PASS
# verdict for each of these by NAME verified nothing. Matched as
# `^PASS[ (partial)] <name> ` so the Python arm's honest `PASS (partial)`
# label counts -- pinning the bare `PASS ` prefix would have quietly
# required the stdlib reader to LIE about its signature limitation.
REQUIRED_VECTOR_NAMES=(
    "corpus_digest"
    "signed/write_v2_signed"
    "signed/write_v2_tampered"
    "signed/equivocation_proof_real"
)

# Sentinels bracketing the fail-closed region in the Rust harness.
GATE_BEGIN='BEGIN conformance fail-closed gate (#2452) -- fail CLOSED'
GATE_END='END conformance fail-closed gate (#2452)'

# Env vars that must never be set in a proving context.
ESCAPE_HATCH_ENV='AI_MEMORY_CONFORMANCE_ALLOW_SKIP'
REGEN_GOLDEN_ENV='AI_MEMORY_REGEN_GOLDEN'

# Phrases that only ever appear in a silent-skip branch.
FAIL_OPEN_PHRASES=(
    'SKIP: python3 not installed'
    'SKIP: node not installed'
    'not exercised'
)

violations=0
violation() {
    printf 'VIOLATION: %s\n' "$*" >&2
    violations=$((violations + 1))
}
info() { printf '%s\n' "$*"; }

# ---------------------------------------------------------------------------
# Reader-spec accessors
# ---------------------------------------------------------------------------
spec_field() { printf '%s' "$1" | cut -d'|' -f"$2"; }

# ---------------------------------------------------------------------------
# G2: resolve an interpreter. Prints the resolved executable on stdout and
# returns 0; returns 1 with the attempt log on stdout when none is usable.
#
# The version STRING decides, never the file name: on Windows images the
# executable is `python.exe`, and a `python3.exe` app-execution-alias stub
# exists that is not an interpreter at all.
# ---------------------------------------------------------------------------
resolve_interpreter() {
    local candidates="$1" marker="$2" c ver tried=""
    for c in $candidates; do
        if ! command -v "$c" >/dev/null 2>&1; then
            tried="${tried}${tried:+; }${c}: not on PATH"
            continue
        fi
        if ! ver="$("$c" --version 2>&1)"; then
            tried="${tried}${tried:+; }${c}: --version failed"
            continue
        fi
        if [[ "$ver" == *"$marker"* ]]; then
            printf '%s' "$c"
            return 0
        fi
        tried="${tried}${tried:+; }${c}: version '${ver//$'\n'/ }' lacks marker '${marker}'"
    done
    printf '%s' "$tried"
    return 1
}

# ---------------------------------------------------------------------------
# G3-G6: run every declared reader over a corpus and assert it VERIFIED.
#
# $1 = corpus root, $2 = scratch dir for captured output.
# Appends human-readable problems to the global CORPUS_MSGS array and sets
# CORPUS_STRUCTURAL / CORPUS_SIGNATURE counts. Callers decide whether a
# problem is a violation (the real gate) or the expected outcome (a plant).
# ---------------------------------------------------------------------------
CORPUS_MSGS=()
CORPUS_STRUCTURAL=0
CORPUS_SIGNATURE=0

problem() { CORPUS_MSGS+=("$*"); }

verify_corpus() {
    local corpus="$1" scratch="$2"
    CORPUS_MSGS=()
    CORPUS_STRUCTURAL=0
    CORPUS_SIGNATURE=0
    mkdir -p "$scratch"

    if [[ ! -f "${corpus}/manifest.json" ]]; then
        problem "corpus manifest missing at ${corpus}/manifest.json"
        return
    fi

    # Filesystem cross-check: the manifest is the reader's own answer key,
    # so an emptied manifest would report a cheerful `1/1 items passed`.
    local record_files
    record_files="$(find "${corpus}/vectors" -name '*.hex' 2>/dev/null | wc -l | tr -d ' ')"
    if (( record_files < MIN_RECORD_FILES )); then
        problem "corpus holds ${record_files} record files, floor is ${MIN_RECORD_FILES} -- vectors were removed, so a green reader run would prove less than it claims"
    fi

    local spec label candidates marker script policy interp out err rc line
    for spec in "${READER_SPECS[@]}"; do
        label="$(spec_field "$spec" 1)"
        candidates="$(spec_field "$spec" 2)"
        marker="$(spec_field "$spec" 3)"
        script="$(spec_field "$spec" 4)"
        policy="$(spec_field "$spec" 5)"

        if [[ ! -f "${corpus}/${script}" ]]; then
            problem "declared ${label} reader missing at ${corpus}/${script}"
            continue
        fi

        # G2 -- ABSENT IS A VIOLATION. Never a skip. This is #2452 itself.
        if ! interp="$(resolve_interpreter "$candidates" "$marker")"; then
            problem "no usable ${label} interpreter (${interp}) -- the >=${REQUIRED_READERS}-non-Rust-reader portability proof CANNOT run here, which is a FAILURE, not a skip (#2452)"
            continue
        fi

        out="${scratch}/${label}.out"
        err="${scratch}/${label}.err"
        rc=0
        # Captured to files, never piped: a pipeline would report the last
        # command's status and launder the reader's own exit code.
        "$interp" "${corpus}/${script}" --corpus "$corpus" >"$out" 2>"$err" || rc=$?

        if (( rc != 0 )); then
            problem "${label} reader run FAILED (exit ${rc}) over ${corpus}: $(head -c 400 "$err" | tr '\n' ' ')"
            continue
        fi
        if grep -q '^FAIL ' "$out"; then
            problem "${label} reader printed a FAIL line despite exit 0: $(grep -m1 '^FAIL ' "$out")"
            continue
        fi
        if grep -q '(FAILURES)' "$out"; then
            problem "${label} reader summary reports (FAILURES) despite exit 0"
            continue
        fi

        # G4 -- the summary, parsed as two integers rather than matched as a
        # literal. `N/M items passed` must have N == M, and M at or above the
        # pinned floor so a shrunken corpus cannot pass by reporting less.
        local summary passed total
        summary="$(grep -Eo '[0-9]+/[0-9]+ items passed' "$out" | tail -n1 || true)"
        if [[ -z "$summary" ]]; then
            problem "${label} reader printed no 'N/M items passed' summary -- an exit-0 run with no summary verified nothing"
            continue
        fi
        passed="${summary%%/*}"
        total="${summary#*/}"
        total="${total%% *}"
        if [[ "$passed" != "$total" ]]; then
            problem "${label} reader passed only ${passed} of ${total} items"
            continue
        fi
        if (( total < MIN_CORPUS_ITEMS )); then
            problem "${label} reader verified ${total} items, floor is ${MIN_CORPUS_ITEMS} -- a shrunken corpus is a weaker proof, not a passing one"
            continue
        fi

        # G4 -- load-bearing verdicts BY NAME. A stub that exits 0 printing
        # nothing (or printing only a summary) must not score as a pass.
        local missing=0
        for line in "${REQUIRED_VECTOR_NAMES[@]}"; do
            if ! grep -qE "^PASS( \\(partial\\))? ${line}[ []" "$out"; then
                problem "${label} reader never reported a PASS verdict for '${line}' -- an exit-0 run that did not verify the signed family is a silent no-op"
                missing=1
            fi
        done
        (( missing == 0 )) || continue

        # G5 -- per-reader honesty pins.
        case "$policy" in
            partial-required)
                if ! grep -qF 'PASS (partial)' "$out"; then
                    problem "${label} reader reported no 'PASS (partial)' -- a stdlib run that cannot check Ed25519 must SAY so, never pass silently"
                    continue
                fi
                ;;
            no-partial)
                if grep -qF 'partial' "$out"; then
                    problem "${label} reader emitted a partial verdict; it is the signature-verifying reader and must fully verify every vector"
                    continue
                fi
                CORPUS_SIGNATURE=$((CORPUS_SIGNATURE + 1))
                ;;
            *) problem "internal error: unknown partial-policy ${policy}"; continue ;;
        esac

        CORPUS_STRUCTURAL=$((CORPUS_STRUCTURAL + 1))
        info "  [${label}] interpreter=${interp} verified ${total}/${total} corpus items (policy=${policy})"
    done

    # G6 -- the COUNT obligation, asserted as a number. Two independent
    # per-reader checks cannot express "at least two".
    if (( CORPUS_STRUCTURAL < REQUIRED_READERS )); then
        problem "only ${CORPUS_STRUCTURAL} of the required ${REQUIRED_READERS} non-Rust readers structurally verified the corpus (ROADMAP 11.6, not relaxed)"
    fi
    if (( CORPUS_SIGNATURE < MIN_SIGNATURE_VERIFYING )); then
        problem "only ${CORPUS_SIGNATURE} reader(s) checked the Ed25519 signatures, floor is ${MIN_SIGNATURE_VERIFYING}"
    fi
}

# ---------------------------------------------------------------------------
# G7-G9: static audits.
# ---------------------------------------------------------------------------
extract_gate_region() {
    awk -v b="$GATE_BEGIN" -v e="$GATE_END" '
        index($0, b) { inside = 1 }
        inside       { print }
        index($0, e) && inside { inside = 0 }
    ' "$1"
}

audit_harness() {
    # $1 = path to the Rust harness
    local file="$1" region phrase aborts
    if [[ ! -f "$file" ]]; then
        violation "Rust conformance harness not found at ${file}"
        return
    fi

    region="$(extract_gate_region "$file")"
    if [[ -z "$region" ]]; then
        violation "harness: no fail-closed gate region found. Expected a block bracketed by '${GATE_BEGIN}' ... '${GATE_END}'. Deleting the gate restores the #2452 silent pass."
        return
    fi

    for phrase in "${FAIL_OPEN_PHRASES[@]}"; do
        if grep -qF -- "$phrase" "$file"; then
            violation "harness: silent-skip phrase '${phrase}' is back. A missing interpreter must FAIL, never print a note and return (#2452)."
        fi
    done

    # Count every occurrence (1 definition + N call sites), so a call site
    # deleted anywhere -- however it is indented -- trips the count.
    aborts="$(grep -o 'fail_closed(' "$file" | wc -l | tr -d ' ')"
    if (( aborts < 4 )); then
        violation "harness: ${aborts} fail_closed( occurrence(s), expected at least 4 (the definition plus a call for: no interpreter / spawn failure / fewer than the required reader count). Deleting an abort branch is the regression."
    fi

    # The region must consult the opt-out (by its const), and the file must
    # spell the variable out, so `grep -r` finds every place it can be set.
    if ! grep -qF -- 'ALLOW_SKIP_ENV' <<<"$region"; then
        violation "harness: the fail-closed region never consults the opt-out const; an unconditional region cannot distinguish 'developer accepted UNPROVEN' from 'CI silently skipped'."
    fi
    if ! grep -qF -- "$ESCAPE_HATCH_ENV" "$file"; then
        violation "harness: the literal ${ESCAPE_HATCH_ENV} is absent; the opt-out must be greppable across the tree."
    fi
    if ! grep -qF -- 'REQUIRED_NON_RUST_READERS' "$file"; then
        violation "harness: no REQUIRED_NON_RUST_READERS count constant -- the '>=2' obligation is then unasserted, which is half of #2452."
    fi

    # The R-203 machinery compiles this file standalone with `rustc --test`.
    # A crate dependency would break that, silently costing the before/after
    # evidence.
    if sed -e 's,//.*$,,' "$file" | grep -qE '(^|[^_[:alnum:]])ai_memory::'; then
        violation "harness: it now depends on the ai_memory crate, so it can no longer be compiled standalone and the R-203 before/after evidence is lost. Keep it std-only."
    fi
}

audit_workflows() {
    local dir="$1" refs
    if [[ ! -d "$dir" ]]; then
        violation "workflow directory not found at ${dir}"
        return
    fi

    # G8 -- the #2452 headline: `grep -rln conformance .github/workflows/`
    # returned NOTHING, so the suite ran in no known environment.
    refs="$(grep -rl -- 'check-conformance-readers.sh' "$dir" 2>/dev/null || true)"
    if [[ -z "$refs" ]]; then
        violation "no workflow references check-conformance-readers.sh -- a gate no workflow runs proves nothing, which is exactly the #2452 finding."
    else
        info "  workflows running this gate: $(printf '%s' "$refs" | tr '\n' ' ')"
    fi

    # G9 -- the escape hatch must never be CI's behaviour.
    local hits
    hits="$(grep -rn -- "$ESCAPE_HATCH_ENV" "$dir" 2>/dev/null || true)"
    if [[ -n "$hits" ]]; then
        violation "a workflow sets ${ESCAPE_HATCH_ENV} (${hits//$'\n'/ ; }). That variable downgrades the proof to UNPROVEN; it is a local-developer escape hatch and is HARD-BLOCKED from CI."
    fi
    hits="$(grep -rn -- "$REGEN_GOLDEN_ENV" "$dir" 2>/dev/null || true)"
    if [[ -n "$hits" ]]; then
        violation "a workflow sets ${REGEN_GOLDEN_ENV} (${hits//$'\n'/ ; }). That toggle REWRITES the committed corpus instead of asserting against it -- CI would then compare the corpus with itself."
    fi
}

audit_runtime_env() {
    # G0 -- a static workflow grep cannot see an org-level or repo-level
    # GitHub `vars`/`env` injection, so check the live process too.
    local v
    for v in "$ESCAPE_HATCH_ENV" "$REGEN_GOLDEN_ENV"; do
        if [[ -n "${!v:-}" ]]; then
            violation "${v} is SET (='${!v}') in the gate's own environment. The proving context must never carry the escape hatch; unset it or remove the org/repo-level variable."
        fi
    done
}

audit_reader_inventory() {
    # The Rust harness and this gate must agree on WHICH readers exist, or
    # one of them is proving something about a reader the other dropped.
    local spec label
    if (( ${#READER_SPECS[@]} < REQUIRED_READERS )); then
        violation "the gate declares ${#READER_SPECS[@]} reader(s) but ROADMAP 11.6 requires ${REQUIRED_READERS}."
    fi
    [[ -f "$HARNESS" ]] || return
    for spec in "${READER_SPECS[@]}"; do
        label="$(spec_field "$spec" 1)"
        if ! grep -qF "label: \"${label}\"" "$HARNESS"; then
            violation "reader '${label}' is declared by this gate but absent from the Rust harness READERS table -- the two proofs have drifted apart."
        fi
    done
}

# ---------------------------------------------------------------------------
# GATE
# ---------------------------------------------------------------------------
run_gate() {
    info "Non-Rust conformance-reader proof gate (#2452)"
    audit_runtime_env
    audit_reader_inventory

    if [[ ! -f "$MANIFEST" ]]; then
        violation "conformance corpus manifest missing at ${MANIFEST}"
    else
        mkdir -p "$SCRATCH_ROOT"
        verify_corpus "$CORPUS_ROOT" "${SCRATCH_ROOT}/$$-gate"
        local msg
        for msg in "${CORPUS_MSGS[@]:-}"; do
            [[ -n "$msg" ]] && violation "$msg"
        done
        rm -rf "${SCRATCH_ROOT}/$$-gate"
    fi

    audit_harness "$HARNESS"
    audit_workflows "$WORKFLOW_DIR"
    rmdir "$SCRATCH_ROOT" 2>/dev/null || true

    if (( violations > 0 )); then
        printf '\nConformance-reader gate: FAIL (%d violation(s))\n' "$violations" >&2
        exit 1
    fi
    info "Conformance-reader gate: PASS (${CORPUS_STRUCTURAL} non-Rust readers structurally verified the corpus; ${CORPUS_SIGNATURE} of them checked the Ed25519 signatures)"
    if (( CORPUS_SIGNATURE < REQUIRED_READERS )); then
        info "  NOTE: PORTABILITY-V2 11.6 asks for ${REQUIRED_READERS} readers that CHECK THE SIGNATURES; only ${CORPUS_SIGNATURE} does today (the Python arm is stdlib-only and labels its signature verdicts 'PASS (partial)'). The shortfall is pinned by MIN_SIGNATURE_VERIFYING, not hidden."
    fi
}

# ---------------------------------------------------------------------------
# SELF-TEST helpers
# ---------------------------------------------------------------------------
expect_corpus_reject() {
    # $1 = label, $2 = mutated corpus dir, $3 = expected violation substring
    local label="$1" dir="$2" want="$3" msg found=0
    verify_corpus "$dir" "${SCRATCH_ROOT}/$$-plant-out" >/dev/null 2>&1 || true
    for msg in "${CORPUS_MSGS[@]:-}"; do
        [[ "$msg" == *"$want"* ]] && found=1
    done
    if (( found == 1 )); then
        printf '  [plant:%-28s] rejected, and for the right reason (%s)\n' "$label" "$want"
    else
        violation "self-test '${label}': the gate did NOT reject with '${want}'. Observed: ${CORPUS_MSGS[*]:-<none>}. A plant that is not caught for the STATED reason is not evidence."
    fi
    rm -rf "${SCRATCH_ROOT}/$$-plant-out"
}

expect_corpus_accept() {
    local label="$1" dir="$2"
    verify_corpus "$dir" "${SCRATCH_ROOT}/$$-ctl-out" >/dev/null 2>&1 || true
    if (( ${#CORPUS_MSGS[@]} == 0 )) && (( CORPUS_STRUCTURAL >= REQUIRED_READERS )); then
        printf '  [control:%-25s] unmutated copy accepted (%d readers verified)\n' "$label" "$CORPUS_STRUCTURAL"
    else
        violation "self-test control '${label}': an UNMUTATED corpus copy did not verify cleanly (${CORPUS_MSGS[*]:-none}; structural=${CORPUS_STRUCTURAL}). Every plant below would then 'pass' for the wrong reason."
    fi
    rm -rf "${SCRATCH_ROOT}/$$-ctl-out"
}

stage_corpus_copy() {
    local dst="$1"
    rm -rf "$dst"
    mkdir -p "$(dirname "$dst")"
    cp -R "$CORPUS_ROOT" "$dst"
}

# Build a PATH holding the tools the gate needs but NO interpreter, so the
# absent-interpreter branch can be exercised against the REAL gate.
make_interpreter_free_path() {
    local dir="$1" t src
    mkdir -p "$dir"
    for t in bash sh env grep awk sed cut tr head tail find wc cp rm mkdir mktemp cat ls dirname basename rmdir uname sort; do
        src="$(command -v "$t" 2>/dev/null || true)"
        if [[ -z "$src" ]]; then
            # NEVER skip-and-pass: a missing prerequisite is a hard failure.
            printf 'SELF-TEST ABORT: required tool %s not on PATH; cannot construct the interpreter-free scenario.\n' "$t" >&2
            exit 1
        fi
        ln -sf "$src" "${dir}/${t}"
    done
}

# ---------------------------------------------------------------------------
# R-203 machinery: compile a `tests/conformance_readers.rs` STANDALONE and
# run it with no interpreters on PATH.
#
# `rustc --test` is used deliberately: the harness is crate-dependency-free
# (G7 keeps it that way), so the before/after behaviour can be demonstrated
# without a cargo build. Two things are asserted SEPARATELY -- that it
# COMPILED, and what it then REPORTED -- because a compile error that got
# scored as "the test failed" would be the same passing-for-the-wrong-reason
# defect this gate exists to remove.
# ---------------------------------------------------------------------------
compile_harness() {
    # $1 = source file, $2 = output binary. Hard-fails on compile error.
    local src="$1" out="$2" log="${2}.compile.log"
    if ! command -v rustc >/dev/null 2>&1; then
        printf 'ABORT: rustc is not on PATH; the R-203 before/after evidence cannot be produced. This is a FAILURE, not a skip (#2452).\n' >&2
        exit 1
    fi
    # `CARGO_MANIFEST_DIR` is consumed by env!() at COMPILE time; without it
    # rustc errors out and the run below would never happen.
    if ! CARGO_MANIFEST_DIR="$REPO_ROOT" rustc --test --edition 2024 \
            "$src" -o "$out" >"$log" 2>&1; then
        printf 'ABORT: standalone compile of %s FAILED (not a test result):\n' "$src" >&2
        head -30 "$log" >&2
        exit 1
    fi
}

# Run a compiled harness with NO interpreter on PATH; echoes the libtest
# summary line.
run_harness_without_interpreters() {
    local bin="$1" minpath="$2" home="$3" out="${1}.run.log"
    # Assert the stripped environment really is interpreter-free, or a
    # leaked `python3` would make the run pass legitimately and the
    # conclusion would be backwards.
    if env -i PATH="$minpath" sh -c 'command -v python3 || command -v python || command -v node' >/dev/null 2>&1; then
        printf 'ABORT: the stripped PATH still exposes an interpreter; the R-203 scenario is not what it claims.\n' >&2
        exit 1
    fi
    env -i PATH="$minpath" HOME="$home" "$bin" --test-threads=1 >"$out" 2>&1 || true
    grep -E '^test result:' "$out" | tail -n1
}

run_self_test() {
    info "Conformance-reader gate: self-test (#2452) -- planting failures against the REAL readers and the REAL harness"
    mkdir -p "$SCRATCH_ROOT"
    local base="${SCRATCH_ROOT}/$$-self" d

    # ---- CONTROL first, or nothing below proves anything ------------------
    d="${base}/control"; stage_corpus_copy "$d"; expect_corpus_accept "unmutated corpus" "$d"

    # ---- P1: a byte flipped in a signed record ---------------------------
    # Proves the PASS lines track the REAL bytes: re-encode-and-compare /
    # length pin / corpus digest must catch it.
    d="${base}/p1"; stage_corpus_copy "$d"
    local v="${d}/vectors/signed/write_v2_signed.hex" body
    body="$(tr -d '\n' <"$v")"
    printf '%s%s\n' "${body:0:$(( ${#body} - 2 ))}" "$( [[ "${body: -2}" == "00" ]] && echo "11" || echo "00" )" >"$v"
    expect_corpus_reject "record byte flipped" "$d" "reader run FAILED"

    # ---- P2: the MUST-REJECT vector re-labelled as VALID ------------------
    # THE decisive plant. The corpus digest covers record BYTES only, so the
    # manifest still checksums clean; the only thing that can catch this is a
    # reader that ACTUALLY VERIFIES the Ed25519 signature. A reader that
    # merely prints PASS lines sails through. This is what separates
    # "two interpreters ran" from "a reader verified".
    d="${base}/p2"; stage_corpus_copy "$d"
    sed -i 's/"verdict": "signature-invalid"/"verdict": "signature-valid"/' "${d}/manifest.json"
    expect_corpus_reject "tampered vector re-labelled valid" "$d" "reader run FAILED"

    # ---- P3: a no-op reader that exits 0 printing nothing ------------------
    # The literal shape of "a control that reports success while doing
    # nothing", planted at the reader itself.
    d="${base}/p3"; stage_corpus_copy "$d"
    printf '#!/usr/bin/env node\nprocess.exit(0);\n' >"${d}/readers/reader.mjs"
    # Caught by the summary check (it prints nothing at all); P4 below is the
    # plant that exercises the verdict-by-name check. Asserting the token the
    # gate ACTUALLY emits is the point -- a plant matched against the wrong
    # reason is how a self-test starts passing for the wrong reason.
    expect_corpus_reject "no-op stub reader" "$d" "printed no 'N/M items passed' summary"

    # ---- P4: a reader that prints a plausible summary but no verdicts -----
    # Defeats a naive "did it print an N/N summary?" check.
    d="${base}/p4"; stage_corpus_copy "$d"
    printf '#!/usr/bin/env node\nconsole.log("\\n18/18 items passed");\n' >"${d}/readers/reader.mjs"
    expect_corpus_reject "summary-only liar reader" "$d" "never reported"

    # ---- P5: vectors deleted from the corpus ------------------------------
    # A shrunken corpus reports a cheerful `N/N items passed`.
    d="${base}/p5"; stage_corpus_copy "$d"
    rm -rf "${d}/vectors/chain"
    expect_corpus_reject "corpus vectors deleted" "$d" "record files"

    # ---- P6: THE #2452 SHAPE -- no interpreter at all ---------------------
    # Runs the REAL, unmodified gate with an interpreter-free PATH and
    # asserts it FAILS naming the absent interpreter. Asserting merely
    # "non-zero" would let an exit-127 harness error masquerade as the gate
    # working, which is how the sibling lane fooled itself twice.
    local minpath="${base}/minbin"
    make_interpreter_free_path "$minpath"
    local rc=0 out
    out="$(env -i PATH="${minpath}" HOME="${base}" bash "${BASH_SOURCE[0]}" 2>&1)" || rc=$?
    if (( rc != 1 )); then
        violation "self-test 'no interpreter': expected the gate to exit 1 (its own refusal), got ${rc}. A 126/127 means the HARNESS broke, not that the gate refused."
    elif ! grep -qF 'no usable python interpreter' <<<"$out"; then
        violation "self-test 'no interpreter': the gate exited 1 without naming the absent interpreter, so this was not the fail-closed refusal being tested. Output: $(head -c 400 <<<"$out")"
    else
        printf '  [plant:%-28s] the REAL gate refused, naming the absent interpreter\n' "no interpreter on PATH"
    fi

    # ---- P7: static plants against the Rust harness -----------------------
    local h="${base}/harness"
    mkdir -p "$h"
    cp "$HARNESS" "${h}/gutted.rs"
    awk -v b="$GATE_BEGIN" -v e="$GATE_END" '
        index($0, b) { skip = 1 }
        !skip        { print }
        index($0, e) { skip = 0 }
    ' "$HARNESS" >"${h}/gutted.rs"
    local before="$violations"
    audit_harness "${h}/gutted.rs" >/dev/null 2>&1 || true
    if (( violations > before )); then
        violations="$before"
        printf '  [plant:%-28s] gutted fail-closed region rejected\n' "harness gate deleted"
    else
        violation "self-test 'harness gate deleted': the static audit accepted a harness with its fail-closed region removed -- the audit is decorative."
    fi

    cp "$HARNESS" "${h}/skippy.rs"
    printf '\n// eprintln!("SKIP: python3 not installed");\n' >>"${h}/skippy.rs"
    before="$violations"
    audit_harness "${h}/skippy.rs" >/dev/null 2>&1 || true
    if (( violations > before )); then
        violations="$before"
        printf '  [plant:%-28s] restored silent-skip phrase rejected\n' "silent-skip phrase back"
    else
        violation "self-test 'silent-skip phrase back': the static audit accepted the restored #2452 SKIP note."
    fi

    # ---- P8: static plants against the workflows --------------------------
    local w="${base}/wf"
    mkdir -p "$w"
    printf 'name: nothing\njobs: {}\n' >"${w}/empty.yml"
    before="$violations"
    audit_workflows "$w" >/dev/null 2>&1 || true
    if (( violations > before )); then
        violations="$before"
        printf '  [plant:%-28s] workflow set with no reference rejected\n' "no workflow runs the gate"
    else
        violation "self-test 'no workflow runs the gate': the audit accepted a workflow set that never invokes this gate -- the original #2452 condition."
    fi

    printf 'env:\n  %s: "1"\n  run: bash scripts/check-conformance-readers.sh\n' "$ESCAPE_HATCH_ENV" >"${w}/hatch.yml"
    before="$violations"
    audit_workflows "$w" >/dev/null 2>&1 || true
    if (( violations > before )); then
        violations="$before"
        printf '  [plant:%-28s] escape hatch in a workflow rejected\n' "escape hatch set in CI"
    else
        violation "self-test 'escape hatch set in CI': the audit accepted a workflow exporting ${ESCAPE_HATCH_ENV}, which downgrades the whole proof to UNPROVEN."
    fi

    # ---- P9: R-203 -- the CURRENT harness must FAIL with no interpreters ---
    # The other half of the before/after pair; `--r203 <ref>` proves the
    # pre-fix file PASSES under the same conditions.
    local bin="${base}/current_harness"
    compile_harness "$HARNESS" "$bin"
    local summary
    summary="$(run_harness_without_interpreters "$bin" "$minpath" "$base")"
    if [[ "$summary" == *"FAILED"* ]]; then
        printf '  [r203-after:%-23s] %s\n' "current harness" "$summary"
    else
        violation "R-203 after: the CURRENT harness reported '${summary}' with NO interpreters on PATH. It must FAIL; a pass here means #2452 is not actually fixed."
    fi
    if ! grep -qF "conformance proof UNPROVABLE (#2452)" "${bin}.run.log"; then
        violation "R-203 after: the current harness failed without emitting the UNPROVABLE token, so the failure was not the fail-closed guard -- it could be any unrelated error."
    fi

    rm -rf "$base"
    rmdir "$SCRATCH_ROOT" 2>/dev/null || true

    if (( violations > 0 )); then
        printf '\nConformance-reader gate self-test: FAIL (%d violation(s)) -- the gate is NOT load-bearing.\n' "$violations" >&2
        exit 1
    fi
    info "Conformance-reader gate self-test: PASS (a corrupted record, a re-labelled MUST-REJECT vector, a no-op reader, a lying reader, a shrunken corpus, an absent interpreter, a gutted harness, a restored SKIP note, an unreferenced workflow set and a CI escape hatch are ALL rejected -- each for the stated reason)"
}

run_r203() {
    local ref="$1" base="${SCRATCH_ROOT}/$$-r203"
    mkdir -p "$base"
    info "Conformance-reader gate: R-203 evidence mode"
    info "  historical harness: ${ref}:tests/conformance_readers.rs"
    info "  expectation: the PRE-FIX harness reports SUCCESS with NO interpreters installed (that is the bug)"

    local old="${base}/old_harness.rs"
    if [[ -f "$ref" ]]; then
        cp "$ref" "$old"
    elif ! git -C "$REPO_ROOT" show "${ref}:tests/conformance_readers.rs" >"$old" 2>/dev/null; then
        printf 'R-203 ABORT: could not read tests/conformance_readers.rs from git ref %s (and it is not a readable path).\n' "$ref" >&2
        exit 1
    fi

    local minpath="${base}/minbin" bin="${base}/old_harness"
    make_interpreter_free_path "$minpath"
    compile_harness "$old" "$bin"     # asserted separately from the run
    local summary
    summary="$(run_harness_without_interpreters "$bin" "$minpath" "$base")"
    info "  libtest summary: ${summary}"

    if [[ "$summary" == *"FAILED"* ]]; then
        printf '\nR-203: NOT reproduced -- %s did not report success with the interpreters absent.\n' "$ref" >&2
        rm -rf "$base"
        exit 1
    fi
    if [[ "$summary" != *"ok."* ]]; then
        printf '\nR-203 ABORT: could not read a libtest summary from the historical harness run (%s).\n' "$summary" >&2
        rm -rf "$base"
        exit 1
    fi
    rm -rf "$base"
    rmdir "$SCRATCH_ROOT" 2>/dev/null || true
    info "R-203 CONFIRMED: ${ref} reports '${summary}' with python3/python/node ALL absent -- the mandated >=${REQUIRED_READERS}-non-Rust-reader proof passed while running nothing."
}

case "${1:-}" in
    "")          run_gate ;;
    --self-test) run_self_test ;;
    --r203)      run_r203 "${2:?usage: $0 --r203 <git-ref-or-path>}" ;;
    -h|--help)   sed -n '3,80p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ;;
    *)
        printf 'usage: %s [--self-test | --r203 <git-ref-or-path>]\n' "$0" >&2
        exit 2
        ;;
esac
