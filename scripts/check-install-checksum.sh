#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Installer checksum fail-CLOSED gate (#2449).
#
# CLASS: "a control that reports success when it did nothing".
#
# Before #2449, `install.sh` TRIED to download `<asset>.sha256`, and when
# that download failed it printed a warning and installed the binary
# anyway (fail-OPEN). `.github/workflows/release.yml` never published a
# `.sha256` asset for the desktop/server tarballs the installer fetches,
# so the download ALWAYS failed and NO install via `install.sh` had ever
# verified the binary it installed. The verification step passed by doing
# nothing, on every install.
#
# This gate is the mechanical guarantee that the class cannot come back.
# It has two modes:
#
#   scripts/check-install-checksum.sh
#     STATIC mode (the CI gate). Asserts, without any network:
#       S1 `install.sh` carries the fail-closed checksum gate region and
#          that region contains no fail-open (warn-and-continue) branch.
#       S2 every concrete artifact `release.yml` uploads to a GitHub
#          release has a sibling `.sha256` in the SAME `files:` list, and
#          every GLOB upload is backed by a whole-directory checksum
#          sweep. This is the durable half: a future PR that adds a new
#          published artifact without a checksum turns CI red.
#     Exit 0 clean, exit 1 on any violation.
#
#   scripts/check-install-checksum.sh --self-test
#     BEHAVIOURAL mode (the load-bearing evidence, pm-v3.2 NO FAIL
#     MISSION closure discipline). PLANTS the failure and proves the
#     REAL, UNMODIFIED `install.sh` rejects it:
#       A  checksum file absent      -> installer MUST abort, MUST NOT install
#       B  checksum file mismatched  -> installer MUST abort, MUST NOT install
#       C  checksum file correct     -> installer MUST succeed and install
#       D  no SHA-256 tool on PATH   -> installer MUST abort, MUST NOT install
#     A gate that is not proven load-bearing is decorative — which is the
#     exact defect #2449 documents. Sibling issue #2452 (a conformance
#     proof that SKIPs-and-PASSes when prerequisites are absent) is why
#     this harness NEVER skips: a missing prerequisite is a FAILURE.
#
#   scripts/check-install-checksum.sh --r203 <git-ref-or-path>
#     R-203 evidence mode. Runs scenario A against a HISTORICAL
#     `install.sh` (a git ref such as the pre-fix base SHA, or a literal
#     path) and asserts it ACCEPTS the unverified tarball — i.e. it
#     reproduces the bug on the old script. Exit 0 means "the bug is
#     confirmed present in that revision".
#
# HOW THE HARNESS WORKS (and why it is trustworthy). It does NOT modify
# `install.sh` and it does NOT rely on any test-only code path inside
# `install.sh`. It prepends a scratch directory to `PATH` holding a
# `curl` (and `wget`) shim that serves the requested URL from a local
# directory and exits 22 (curl's HTTP-error code) when the file is
# absent. The script under test is therefore the byte-identical shipped
# script, exercising its real URL construction, its real `download()`
# failure handling, and its real verification branch.
#
# Scratch lives under `.local-runs/` per the project hard rule — never
# `/tmp`, `/var/tmp`, or any tmpfs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="${REPO_ROOT}/install.sh"
WORKFLOW="${REPO_ROOT}/.github/workflows/release.yml"
SCRATCH_ROOT="${REPO_ROOT}/.local-runs/check-install-checksum"

# Sentinels that bracket the fail-closed region in the installers. The
# static mode extracts exactly this region and audits it; renaming or
# deleting the sentinels is itself a violation.
GATE_BEGIN='BEGIN checksum gate (#2449) -- fail CLOSED'
GATE_END='END checksum gate (#2449)'
# Sentinel that marks a whole-directory checksum sweep in release.yml.
SWEEP_SENTINEL='checksum-sweep (#2449)'

# Phrases that only ever appear in a warn-and-continue (fail-open)
# checksum branch. Their presence anywhere in the gate region is the
# #2449 regression itself.
FAIL_OPEN_PHRASES=(
    'skipping checksum verification'
    'skipping verification'
    'Checksum file not available'
)

violations=0
violation() {
    printf 'VIOLATION: %s\n' "$*" >&2
    violations=$((violations + 1))
}
info() { printf '%s\n' "$*"; }

# ---------------------------------------------------------------------------
# STATIC: extract the bracketed fail-closed region from an installer.
# ---------------------------------------------------------------------------
extract_gate_region() {
    # $1 = file
    awk -v b="$GATE_BEGIN" -v e="$GATE_END" '
        index($0, b) { inside = 1 }
        inside       { print }
        index($0, e) && inside { inside = 0 }
    ' "$1"
}

audit_installer_region() {
    # $1 = label, $2 = file, $3 = minimum number of hard-abort statements,
    # $4 = regex matching a hard abort in that language
    local label="$1" file="$2" min_aborts="$3" abort_re="$4"
    local region abort_count phrase

    if [[ ! -f "$file" ]]; then
        violation "${label}: file not found at ${file}"
        return
    fi

    region="$(extract_gate_region "$file")"
    if [[ -z "$region" ]]; then
        violation "${label}: no fail-closed checksum gate region found. Expected a block bracketed by '${GATE_BEGIN}' ... '${GATE_END}'. Deleting the gate is the #2449 regression."
        return
    fi

    for phrase in "${FAIL_OPEN_PHRASES[@]}"; do
        if grep -qiF -- "$phrase" <<<"$region"; then
            violation "${label}: fail-open phrase '${phrase}' inside the checksum gate. A missing/unverifiable checksum must ABORT, never warn-and-continue (#2449)."
        fi
    done

    abort_count="$(grep -cE -- "$abort_re" <<<"$region" || true)"
    if (( abort_count < min_aborts )); then
        violation "${label}: checksum gate has ${abort_count} hard-abort statement(s), expected at least ${min_aborts} (missing checksum / malformed checksum / no hashing tool / mismatch)."
    fi

    if ! grep -qF -- 'CHECKSUM_URL' <<<"$region" && ! grep -qF -- 'ChecksumUrl' <<<"$region"; then
        violation "${label}: checksum gate never references the checksum URL — it cannot be verifying anything."
    fi

    # These scripts are piped straight into `sh` / `iex` on machines whose
    # locale we do not control. #1880 is the standing lesson: one stray
    # non-ASCII byte (a U+2014 em-dash) in a cloud-init template made
    # cloud-init silently discard the whole config. Both installers were
    # pure ASCII before #2449 and must stay that way.
    if LC_ALL=C grep -qn '[^ -~	]' "$file"; then
        violation "${label}: non-ASCII byte(s) at line(s) $(LC_ALL=C grep -n '[^ -~	]' "$file" | cut -d: -f1 | paste -sd, -). A script piped into sh/iex must stay pure ASCII (#1880)."
    fi
}

# ---------------------------------------------------------------------------
# STATIC: every published artifact must carry a sibling checksum.
#
# Parses every `files:` list handed to softprops/action-gh-release in
# release.yml. For each CONCRETE entry (no glob) that is a release
# artifact, a sibling `<entry>.sha256` must appear in the SAME list. For
# each GLOB entry, the workflow must carry a whole-directory checksum
# sweep, because a glob will happily publish a future artifact that
# nobody remembered to checksum.
# ---------------------------------------------------------------------------
audit_workflow_checksums() {
    if [[ ! -f "$WORKFLOW" ]]; then
        violation "release workflow not found at ${WORKFLOW}"
        return
    fi

    local entries glob_seen=0 concrete_total=0
    # Collect every path that appears under a `files:` key, in either the
    # inline (`files: dist/x`) or the block (`files: |`) form.
    entries="$(
        awk '
            /^[[:space:]]*files:[[:space:]]*\|[[:space:]]*$/ { block = 1; next }
            /^[[:space:]]*files:[[:space:]]*[^|[:space:]]/ {
                sub(/^[[:space:]]*files:[[:space:]]*/, "")
                print
                next
            }
            block {
                if ($0 ~ /^[[:space:]]*$/) { next }
                # a new key at or below the `files:` indentation ends the block
                if ($0 ~ /^[[:space:]]*[A-Za-z_-]+:/) { block = 0; next }
                gsub(/^[[:space:]]+|[[:space:]]+$/, "")
                print
            }
        ' "$WORKFLOW" | sed 's/[[:space:]]*#.*$//' | grep -v '^$' || true
    )"

    if [[ -z "$entries" ]]; then
        violation "release.yml: could not parse any release-upload 'files:' entries — the audit would vacuously pass, which is the #2449 defect class."
        return
    fi

    local e
    while IFS= read -r e; do
        [[ -z "$e" ]] && continue
        if [[ "$e" == *"*"* ]]; then
            glob_seen=1
            continue
        fi
        # Only artifacts are checksummed; `.sha256` files are the checksums.
        case "$e" in
            *.sha256) continue ;;
            *.tar.gz|*.tgz|*.zip|*.json|*.deb|*.rpm|*.xz) ;;
            *) continue ;;
        esac
        concrete_total=$((concrete_total + 1))
        if ! grep -qxF -- "${e}.sha256" <<<"$entries"; then
            violation "release.yml: release artifact '${e}' is published with no sibling '${e}.sha256' in the same files: list. An installer cannot verify what the release does not publish (#2449)."
        fi
    done <<<"$entries"

    if (( glob_seen == 1 )); then
        local sweeps
        sweeps="$(grep -cF -- "$SWEEP_SENTINEL" "$WORKFLOW" || true)"
        if (( sweeps < 1 )); then
            violation "release.yml: a GLOB upload publishes every file in dist/, but ${sweeps} '${SWEEP_SENTINEL}' step(s) were found (expected >= 1: the whole-directory sweep covering every release leg). Without a whole-directory sweep a future artifact ships unchecksummed."
        fi
    fi

    info "  release.yml: ${concrete_total} concrete artifact entr(y|ies) audited; glob upload sweep required: $([[ $glob_seen == 1 ]] && echo yes || echo no)"
}

run_static() {
    info "Installer checksum gate: static mode (#2449)"
    # Match the indented CALL sites of each installer's canonical abort
    # helper, not its definition — so deleting an abort branch (rather
    # than merely renaming the helper) is what trips the count.
    audit_installer_region "install.sh"  "$INSTALLER"     4 '^[[:space:]]+abort_unverified[[:space:]]*$'
    audit_workflow_checksums

    if (( violations > 0 )); then
        printf '\nInstaller checksum gate: FAIL (%d violation(s))\n' "$violations" >&2
        exit 1
    fi
    info "Installer checksum gate: PASS (installers fail CLOSED; every published artifact carries a checksum)"
}

# ---------------------------------------------------------------------------
# BEHAVIOURAL harness
# ---------------------------------------------------------------------------

# Tools the installer legitimately needs, beyond the download client. The
# scenario-D minimal PATH is built from exactly this list, so a SHA-256
# tool can be withheld without withholding anything else.
MIN_TOOLS=(sh env gzip uname mktemp rm mkdir cp chmod tar awk wc tr ls cat sed grep)

# Every fail-closed abort in install.sh prints this line.
# Reject scenarios must see it, so that a harness-level failure (a missing
# tool, exit 127, a typo in the invocation) can never masquerade as "the
# installer correctly refused". Asserting only "exit != 0" is how a
# self-test passes for the wrong reason.
REFUSAL_MARKER='install aborted (checksum gate #2449)'

make_shims() {
    # $1 = bin dir, $2 = serve dir
    local bin="$1" serve="$2"
    mkdir -p "$bin"

    cat >"${bin}/curl" <<SHIM
#!/bin/sh
# Test double for curl(1). Serves \$SERVE/asset for any non-.sha256 URL and
# \$SERVE/checksum for a .sha256 URL; exits 22 (curl's HTTP-error code) when
# the backing file is absent, exactly as curl -f does on a 404.
SERVE='${serve}'
url=''
dest=''
while [ \$# -gt 0 ]; do
    case "\$1" in
        -o) shift; dest="\$1" ;;
        -*) : ;;
        *)  url="\$1" ;;
    esac
    shift
done
case "\$url" in
    *.sha256) src="\$SERVE/checksum" ;;
    *)        src="\$SERVE/asset" ;;
esac
[ -f "\$src" ] || exit 22
[ -n "\$dest" ] || { cat "\$src"; exit 0; }
cp "\$src" "\$dest"
SHIM

    # wget double, same semantics (-q URL -O dest), so the harness is
    # honest on hosts where install.sh would take the wget branch.
    cat >"${bin}/wget" <<SHIM
#!/bin/sh
SERVE='${serve}'
url=''
dest=''
while [ \$# -gt 0 ]; do
    case "\$1" in
        -O) shift; dest="\$1" ;;
        -*) : ;;
        *)  url="\$1" ;;
    esac
    shift
done
case "\$url" in
    *.sha256) src="\$SERVE/checksum" ;;
    *)        src="\$SERVE/asset" ;;
esac
[ -f "\$src" ] || exit 8
[ -n "\$dest" ] || { cat "\$src"; exit 0; }
cp "\$src" "\$dest"
SHIM

    chmod +x "${bin}/curl" "${bin}/wget"
}

make_min_path() {
    # $1 = dir to populate with symlinks to MIN_TOOLS, $2.. = extra tools.
    # Notably absent: sha256sum and shasum, so the installer's hashing
    # ladder can be driven down to a chosen rung.
    local dir="$1"; shift
    local t src
    mkdir -p "$dir"
    for t in "${MIN_TOOLS[@]}" "$@"; do
        src="$(command -v "$t" 2>/dev/null || true)"
        if [[ -z "$src" ]]; then
            # NEVER skip-and-pass (#2452's defect class): a missing
            # prerequisite is a hard failure, not a silent PASS.
            printf 'SELF-TEST ABORT: required tool %s not found on PATH; cannot construct the no-hashing-tool scenario.\n' "$t" >&2
            exit 1
        fi
        ln -sf "$src" "${dir}/${t}"
    done
}

make_asset() {
    # $1 = serve dir. Builds a tarball whose single member is `ai-memory`,
    # which is what install.sh extracts and installs.
    local serve="$1" stage
    stage="${serve}/stage"
    mkdir -p "$stage"
    cat >"${stage}/ai-memory" <<'BIN'
#!/bin/sh
# test double for the ai-memory binary
exit 0
BIN
    chmod +x "${stage}/ai-memory"
    tar czf "${serve}/asset" -C "$stage" ai-memory
    rm -rf "$stage"
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        printf 'SELF-TEST ABORT: no sha256sum/shasum on the harness host.\n' >&2
        exit 1
    fi
}

# run_scenario <name> <installer> <checksum-mode> <expect> [minimal-path]
#   checksum-mode : none | bad | good
#   expect        : reject | accept
run_scenario() {
    local name="$1" installer="$2" mode="$3" expect="$4" minimal="${5:-no}"
    local case_dir serve bin target rc=0 out path

    case_dir="${SCRATCH_ROOT}/$$-${name}"
    rm -rf "$case_dir"
    serve="${case_dir}/serve"
    bin="${case_dir}/bin"
    target="${case_dir}/target"
    mkdir -p "$serve" "$target"

    make_asset "$serve"
    make_shims "$bin" "$serve"

    case "$mode" in
        none) : ;;  # deliberately no checksum file -> shim 404s
        bad)  printf '%s  asset\n' "$(printf '%064d' 0)" >"${serve}/checksum" ;;
        good) printf '%s  asset\n' "$(sha256_of "${serve}/asset")" >"${serve}/checksum" ;;
        *)    printf 'internal error: bad checksum mode %s\n' "$mode" >&2; exit 1 ;;
    esac

    case "$minimal" in
        no)      path="${bin}:${PATH}" ;;
        # No SHA-256 tool at all -> the installer must abort.
        yes)     make_min_path "${case_dir}/min";         path="${bin}:${case_dir}/min" ;;
        # openssl is the ONLY hasher -> drives the third rung of the
        # hashing ladder, so that rung is proven rather than assumed.
        # (The vote's abort-only camp objected precisely that an
        # unexercised fallback branch is the fail-open bug one layer
        # down; these two scenarios are what answers that.)
        openssl) make_min_path "${case_dir}/min" openssl; path="${bin}:${case_dir}/min" ;;
        *) printf 'internal error: bad minimal mode %s\n' "$minimal" >&2; exit 1 ;;
    esac

    # PSModulePath / POWERSHELL_DISTRIBUTION_CHANNEL are scrubbed defensively
    # so the child sees a clean, reproducible environment regardless of the
    # host shell (GitHub's ubuntu runners ship PowerShell and export
    # PSModulePath process-wide). `env` is resolved from the harness's own
    # PATH before the replacement PATH is applied to the child.
    set +e
    out="$(env -u PSModulePath -u POWERSHELL_DISTRIBUTION_CHANNEL \
              PATH="$path" HOME="$case_dir" \
              sh "$installer" --dir "$target" 2>&1)"
    rc=$?
    set -e

    local installed=no
    [[ -f "${target}/ai-memory" ]] && installed=yes

    local verdict=accept
    if (( rc != 0 )); then verdict=reject; fi

    printf '  [%s] mode=%-4s exit=%-3d installed=%-3s expected=%s\n' \
        "$name" "$mode" "$rc" "$installed" "$expect"

    local ok=1 why=""
    if [[ "$expect" == "reject" ]]; then
        # Exit 1 specifically — install.sh aborts with `exit 1`. A 126/127
        # (tool missing, not executable) means the HARNESS broke, not that
        # the installer refused, and must not be scored as a pass.
        (( rc == 1 )) || { ok=0; why="expected exit 1 (the installer's own abort), got ${rc}"; }
        [[ "$installed" == "no" ]] || { ok=0; why="the binary was installed anyway"; }
        if ! grep -qF -- "$REFUSAL_MARKER" <<<"$out"; then
            ok=0
            why="${why:+${why}; }the refusal marker '${REFUSAL_MARKER}' was absent, so this was not a deliberate fail-closed refusal"
        fi
    else
        (( rc == 0 )) || { ok=0; why="expected exit 0, got ${rc}"; }
        [[ "$installed" == "yes" ]] || { ok=0; why="${why:+${why}; }the binary was not installed"; }
    fi

    if (( ok == 0 )); then
        violation "scenario ${name}: expected the installer to ${expect}, but ${why}."
        printf -- '--- installer output (%s) ---\n%s\n--- end ---\n' "$name" "$out" >&2
    fi

    rm -rf "$case_dir"
}

# ---------------------------------------------------------------------------
# STATIC self-test: prove the static gate is load-bearing by planting the
# exact regressions it exists to catch into a throwaway copy of the repo
# (under .local-runs/, never /tmp) and asserting the gate rejects each.
#
# Without this, the static mode is an assertion nobody has ever seen fail
# — which is the same "decorative control" defect #2449 is about, one
# level up.
# ---------------------------------------------------------------------------
stage_repo_copy() {
    local dst="$1"
    rm -rf "$dst"
    mkdir -p "${dst}/scripts" "${dst}/.github/workflows"
    cp "${BASH_SOURCE[0]}" "${dst}/scripts/check-install-checksum.sh"
    cp "$INSTALLER"        "${dst}/install.sh"
    cp "$WORKFLOW"         "${dst}/.github/workflows/release.yml"
    chmod +x "${dst}/scripts/check-install-checksum.sh"
}

expect_static() {
    # $1 = label, $2 = staged dir, $3 = pass|fail
    local label="$1" dir="$2" want="$3" rc=0
    "${dir}/scripts/check-install-checksum.sh" >/dev/null 2>&1 || rc=$?
    if [[ "$want" == "pass" ]]; then
        if (( rc != 0 )); then
            violation "static self-test '${label}': the gate FAILED on an unmutated copy (exit ${rc}) — every subsequent plant would 'pass' for the wrong reason."
        else
            printf '  [static:%-26s] unmutated copy accepted (control)\n' "$label"
        fi
    else
        if (( rc == 0 )); then
            violation "static self-test '${label}': the gate PASSED on a planted regression — the static gate is decorative, not load-bearing."
        else
            printf '  [static:%-26s] planted regression rejected\n' "$label"
        fi
    fi
}

run_static_self_test() {
    local base="${SCRATCH_ROOT}/$$-static" d

    # Control first: an untouched copy MUST pass, or the plants below
    # prove nothing.
    d="${base}/control"; stage_repo_copy "$d"; expect_static "control (unmutated)" "$d" pass

    # P1 — the whole fail-closed region deleted from install.sh.
    d="${base}/p1"; stage_repo_copy "$d"
    awk -v b="$GATE_BEGIN" -v e="$GATE_END" '
        index($0, b) { skip = 1 }
        !skip        { print }
        index($0, e) { skip = 0 }
    ' "${d}/install.sh" >"${d}/install.sh.tmp" && mv "${d}/install.sh.tmp" "${d}/install.sh"
    expect_static "install.sh gate deleted" "$d" fail

    # P2 — the exact #2449 warn-and-continue branch put back.
    d="${base}/p2"; stage_repo_copy "$d"
    sed -i 's|^    echo "Verifying checksum\.\.\."$|    echo "Warning: Checksum file not available, skipping verification."|' "${d}/install.sh"
    expect_static "install.sh fail-open phrase" "$d" fail

    # P3 — an abort branch removed (the gate counts abort sites, so
    # weakening the region without deleting it is still caught).
    d="${base}/p3"; stage_repo_copy "$d"
    python3 - "$d" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]) / "install.sh"
s = p.read_text()
# Drop two of the five abort sites.
p.write_text(s.replace("        abort_unverified\n", "        :\n", 2))
PY
    expect_static "install.sh abort branch removed" "$d" fail

    # P4 — the release.yml checksum sweep steps deleted, which is how the
    # glob-published tarballs silently lose their .sha256 again.
    d="${base}/p4"; stage_repo_copy "$d"
    sed -i "s|# ${SWEEP_SENTINEL}||g" "${d}/.github/workflows/release.yml"
    expect_static "release.yml sweep removed" "$d" fail

    # P5 — a concrete artifact published with its sibling .sha256 entry
    # dropped from the same files: list (how a NEW artifact type would
    # ship unverified).
    d="${base}/p5"; stage_repo_copy "$d"
    sed -i '/dist\/ai-memory-ios\.xcframework\.tar\.gz\.sha256/d' "${d}/.github/workflows/release.yml"
    expect_static "release.yml sibling dropped" "$d" fail

    rm -rf "$base"
}

run_self_test() {
    info "Installer checksum gate: self-test mode (#2449) — planting failures against the REAL install.sh"
    info "  installer under test: ${INSTALLER}"
    mkdir -p "$SCRATCH_ROOT"

    # The two scenarios #2449 is about: the control must REFUSE.
    run_scenario missing-checksum      "$INSTALLER" none reject
    run_scenario mismatched-checksum   "$INSTALLER" bad  reject
    # ... and it must still let a good install through, or it is not a
    # gate, it is an outage.
    run_scenario valid-checksum        "$INSTALLER" good accept
    # No hashing tool at all: abort, never "skip verification".
    run_scenario no-sha256-tool        "$INSTALLER" good reject yes
    # openssl as the ONLY hasher: the third rung must really verify —
    # accept a correct digest AND reject a wrong one. A rung that
    # accepted everything would be the original bug in a new shape.
    run_scenario openssl-rung-valid    "$INSTALLER" good accept openssl
    run_scenario openssl-rung-mismatch "$INSTALLER" bad  reject openssl

    info "  --- static gate, planted regressions ---"
    run_static_self_test

    rmdir "$SCRATCH_ROOT" 2>/dev/null || true

    if (( violations > 0 )); then
        printf '\nInstaller checksum gate self-test: FAIL (%d violation(s)) — the installer is NOT fail-closed.\n' "$violations" >&2
        exit 1
    fi
    info "Installer checksum gate self-test: PASS (missing / mismatched checksum and a missing SHA-256 tool are all REJECTED; a valid checksum installs)"
}

run_r203() {
    # $1 = git ref or path to a historical install.sh
    local ref="$1" old="${SCRATCH_ROOT}/r203-install.sh"
    mkdir -p "$SCRATCH_ROOT"

    if [[ -f "$ref" ]]; then
        cp "$ref" "$old"
    else
        if ! git -C "$REPO_ROOT" show "${ref}:install.sh" >"$old" 2>/dev/null; then
            printf 'R-203 ABORT: could not read install.sh from git ref %s (and it is not a readable path).\n' "$ref" >&2
            exit 1
        fi
    fi

    info "Installer checksum gate: R-203 evidence mode"
    info "  historical installer: ${ref}"
    info "  expectation: the PRE-FIX installer ACCEPTS a tarball with NO checksum (that is the bug)"

    run_scenario r203-missing-checksum "$old" none accept

    rm -f "$old"
    rmdir "$SCRATCH_ROOT" 2>/dev/null || true

    if (( violations > 0 )); then
        printf '\nR-203: NOT reproduced — %s did not accept an unverified tarball.\n' "$ref" >&2
        exit 1
    fi
    info "R-203 CONFIRMED: ${ref} installs an unverified binary when no checksum is published."
}

case "${1:-}" in
    "")          run_static ;;
    --self-test) run_self_test ;;
    --r203)      run_r203 "${2:?usage: $0 --r203 <git-ref-or-path>}" ;;
    -h|--help)
        sed -n '3,60p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
        ;;
    *)
        printf 'usage: %s [--self-test | --r203 <git-ref-or-path>]\n' "$0" >&2
        exit 2
        ;;
esac
