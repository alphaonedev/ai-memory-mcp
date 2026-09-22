#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# scripts/check-sdk-tls-scheme.sh
#
# v1.0.0 #3782 — SDK TLS-SCHEME gate (adopter lens, 3x7 workstream G on
# PR #3769).
#
# THE DEFECT THIS CLOSES. Since #3705/#3709 every daemon listener serves
# TLS: `src/daemon_runtime.rs` `tls_bind_guard` refuses to bind a
# plaintext listener ("There is no plaintext posture to select"),
# loopback included, and `resolve_tls_material` refuses the boot rather
# than downgrade. Both SDK quickstarts, both SDK clients' DEFAULT base
# URL and 36 further occurrences under `sdk/` still said
# `http://localhost:9077` — a scheme no daemon will ever answer. Every
# adopter following the quickstart failed on their FIRST call. The
# acceptance harness carried the identical defect (#3776).
#
# THE RULE IS A PAIR (absence + presence, rule fa41723f). Rewriting the
# scheme alone is not a fix: `https://localhost:9077` against a
# zero-config daemon fails certificate verification, because the daemon
# serves a leaf issued by the local CA it generated on first boot
# (`<key_dir>/tls/local-ca.pem`, `src/tls_bootstrap.rs`) which no public
# root signs. An adopter who is told "use https" and not "here is the CA
# and here is the client option that pins it" fails on the first call
# just the same, only with a different error. So this gate asserts BOTH
# halves and fails if either is missing:
#
#   ABSENCE  — no `http://localhost` / `http://127.0.0.1` anywhere under
#              `sdk/` (examples, defaults, tests, READMEs alike).
#   PRESENCE — BOTH SDK READMEs carry a CA-trust section: the heading,
#              the CA FILE (`local-ca.pem`) and the client option that
#              pins it (`verify=` for python, `caCert` for TypeScript).
#              A heading with no file name and no option is a stub and
#              is REJECTED — the presence half must name the two things
#              an adopter cannot guess.
#
# The absence half is a RAW-TEXT rule here, deliberately unlike
# `check-sdk-route-paths.sh`'s call-site-only rule: there is no
# legitimate reason for the string `http://localhost` to survive
# anywhere in a shipped SDK, not in a comment and not in prose, because
# a reader who copies it gets a connection that cannot work. Prose that
# needs to discuss the old scheme says "plaintext" or "http://" without
# the host.
#
# Scan set is `sdk/**` by PATTERN, never an enumerated list (#2444: a
# gate that can no-op to green is worse than no gate), with build and
# dependency output excluded.
#
# CLI:
#   scripts/check-sdk-tls-scheme.sh              — run the gate (exit 0/1)
#   scripts/check-sdk-tls-scheme.sh --self-test  — plant the defect in a
#       throwaway fixture UNDER `.local-runs/` (never system /tmp, never
#       `mktemp -d` outside the repo) and prove the gate rejects each
#       half, alongside NEAR-MISS controls that must each PASS so the
#       rule is shown to fire on the defect and not on its neighbourhood.
#
# Exit codes: 0 clean, 1 violation, 2 scanner/usage/self-test failure.

set -euo pipefail

# The two halves of the rule, as literals, so the gate body and the
# self-test cannot drift apart.
FORBIDDEN_RE='http://(localhost|127\.0\.0\.1)'
CA_HEADING_RE='^#+[[:space:]]+Trust the daemon'"'"'s CA[[:space:]]*$'
CA_FILE_LITERAL='local-ca.pem'

# --------------------------------------------------------------------
# Gate body. Prints violations to stderr; returns 0 clean / 1 violation
# / 2 scanner failure (fail CLOSED, never a silent PASS).
# --------------------------------------------------------------------
run_gate() {
    local root="$1"
    local sdk="$root/sdk"
    local fail=0

    # Fail-closed self-test fault injection (#2713 shape). Never set in
    # production or CI; only the gate's own --self-test sets it, to prove
    # a scanner error exits non-zero with NO pass banner.
    if [[ -n "${AI_MEMORY_SDK_TLS_GATE_SELFTEST_FAULT:-}" ]]; then
        printf 'FAIL: check-sdk-tls-scheme: scanner errored (injected self-test fault) — refusing to report PASS\n' >&2
        return 2
    fi

    if [[ ! -d "$sdk" ]]; then
        printf 'FAIL: check-sdk-tls-scheme: no sdk/ directory under %s (gate would be a no-op)\n' "$root" >&2
        return 2
    fi

    # ---- scan set, by PATTERN ---------------------------------------
    local files=()
    while IFS= read -r f; do
        files+=("$f")
    done < <(
        find "$sdk" -type f \
            \( -name '*.ts' -o -name '*.js' -o -name '*.py' -o -name '*.md' \
               -o -name '*.json' -o -name '*.toml' -o -name '*.sh' \) \
            -not -path '*/node_modules/*' -not -path '*/dist/*' \
            -not -path '*/__pycache__/*' -not -path '*/.venv/*' \
            2>/dev/null | sort
    )
    if [[ "${#files[@]}" -eq 0 ]]; then
        printf 'FAIL: check-sdk-tls-scheme: scanned ZERO files under %s (gate would be a no-op, #2444)\n' "$sdk" >&2
        return 2
    fi

    # ---- half 1: ABSENCE --------------------------------------------
    local hits status=0
    hits="$(LC_ALL=C grep -nE "$FORBIDDEN_RE" "${files[@]}" 2>/dev/null)" || status=$?
    if [[ "$status" -gt 1 ]]; then
        printf 'FAIL: check-sdk-tls-scheme: scanner exited %s — refusing to report PASS\n' "$status" >&2
        return 2
    fi
    if [[ -n "$hits" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            printf 'FAIL: check-sdk-tls-scheme: plaintext daemon URL under sdk/: %s\n' \
                "${line#"$root/"}" >&2
            fail=$((fail + 1))
        done <<<"$hits"
    fi

    # ---- half 2: PRESENCE -------------------------------------------
    local readme
    for readme in "$sdk/python/README.md" "$sdk/typescript/README.md"; do
        if [[ ! -f "$readme" ]]; then
            printf 'FAIL: check-sdk-tls-scheme: SDK README missing: %s\n' "${readme#"$root/"}" >&2
            fail=$((fail + 1))
            continue
        fi
        if ! LC_ALL=C grep -qE "$CA_HEADING_RE" "$readme"; then
            printf 'FAIL: check-sdk-tls-scheme: %s has no "Trust the daemon'"'"'s CA" section\n' \
                "${readme#"$root/"}" >&2
            fail=$((fail + 1))
            continue
        fi
        if ! LC_ALL=C grep -qF "$CA_FILE_LITERAL" "$readme"; then
            printf 'FAIL: check-sdk-tls-scheme: %s has the CA-trust heading but never names %s\n' \
                "${readme#"$root/"}" "$CA_FILE_LITERAL" >&2
            fail=$((fail + 1))
            continue
        fi
        # The client option that PINS the CA. Each SDK exposes its own;
        # naming the file without naming the option leaves the adopter
        # exactly where the defect left them.
        local opt_re
        case "$readme" in
            */python/README.md) opt_re='verify=' ;;
            *) opt_re='caCert' ;;
        esac
        if ! LC_ALL=C grep -qF "$opt_re" "$readme"; then
            printf 'FAIL: check-sdk-tls-scheme: %s names %s but not the client option that pins it (%s)\n' \
                "${readme#"$root/"}" "$CA_FILE_LITERAL" "$opt_re" >&2
            fail=$((fail + 1))
        fi
    done

    if [[ "$fail" -gt 0 ]]; then
        printf '\n❌ SDK TLS-scheme gate (#3782): %d violation(s)\n' "$fail" >&2
        printf '   Every daemon listener serves TLS since #3705/#3709 — `tls_bind_guard`\n' >&2
        printf '   refuses a plaintext listener, loopback included. SDK examples and\n' >&2
        printf '   defaults must use https://, and BOTH SDK READMEs must tell the adopter\n' >&2
        printf '   where the daemon-generated CA lives (<key_dir>/tls/%s) and\n' "$CA_FILE_LITERAL" >&2
        printf '   which client option pins it.\n' >&2
        return 1
    fi
    printf '✅ SDK TLS-scheme gate (#3782): PASS (%d sdk files scanned; both READMEs carry the CA-trust section)\n' \
        "${#files[@]}"
    return 0
}

# --------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------
if [[ "${1:-}" == "--self-test" ]]; then
    ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
    FIX="$ROOT/.local-runs/sdk-tls-scheme-selftest-$$"
    rm -rf "$FIX"
    mkdir -p "$FIX"
    trap 'rm -rf "$FIX"' EXIT

    run_fixture() { ( AI_MEMORY_SDK_TLS_GATE_ROOT="$FIX" "$SELF" >/dev/null 2>&1; echo "$?" ); }
    run_fixture_out() { AI_MEMORY_SDK_TLS_GATE_ROOT="$FIX" "$SELF" 2>&1 || true; }

    write_clean() {
        rm -rf "$FIX/sdk" "$FIX/docs"
        mkdir -p "$FIX/sdk/python/ai_memory" "$FIX/sdk/typescript/src" "$FIX/docs"
        # NEAR-MISS CONTROLS — every one of these must PASS, so the rule
        # is shown to fire on the DEFECT and not on its neighbourhood:
        #  * the corrected https loopback URLs, in both host spellings
        #  * an abstract mock host over http (`http://mock`), which is
        #    not a daemon URL and which the swarm tests legitimately use
        #  * a public http URL that is not loopback
        #  * `http://localhost` OUTSIDE sdk/ (docs/), which this gate
        #    must not police
        cat > "$FIX/sdk/python/ai_memory/_common.py" <<'PYEOF'
DEFAULT_BASE_URL = "https://localhost:9077"
MOCK = "http://mock"
UPSTREAM = "http://example.com/spec"
PYEOF
        cat > "$FIX/sdk/typescript/src/client.ts" <<'TSEOF'
const base = "https://127.0.0.1:9077";
const alt = "https://localhost:9077";
TSEOF
        printf 'Legacy note: the daemon once listened on http://localhost:9077.\n' \
            > "$FIX/docs/history.md"
        cat > "$FIX/sdk/python/README.md" <<'MDEOF'
# ai-memory — Python SDK

## Trust the daemon's CA

The CA is `<key_dir>/tls/local-ca.pem`. Pin it with `verify=str(ca)`.
MDEOF
        cat > "$FIX/sdk/typescript/README.md" <<'MDEOF'
# ai-memory — TypeScript SDK

## Trust the daemon's CA

The CA is `<key_dir>/tls/local-ca.pem`. Pin it with the `caCert` option.
MDEOF
    }

    write_clean
    rc="$(run_fixture)"
    if [[ "$rc" != "0" ]]; then
        echo "FAIL: self-test — the CLEAN near-miss control tree was REJECTED (exit $rc)." >&2
        run_fixture_out | sed 's/^/       /' >&2
        exit 2
    fi
    echo "PASS: self-test control — https loopback URLs, http://mock, a public http URL, and http://localhost OUTSIDE sdk/ all PASS"

    # ---- ABSENCE half ------------------------------------------------
    write_clean
    printf 'BAD = "http://localhost:9077"\n' >> "$FIX/sdk/python/ai_memory/_common.py"
    [[ "$(run_fixture)" != "0" ]] || { echo "FAIL: self-test absence — http://localhost in a python default ACCEPTED" >&2; exit 2; }
    run_fixture_out | grep -q 'plaintext daemon URL' || {
        echo "FAIL: self-test absence — violation reported without the plaintext-URL message" >&2; exit 2; }
    echo "PASS: self-test absence — http://localhost in an SDK default is REJECTED"

    write_clean
    printf 'const dead = "http://127.0.0.1:9077";\n' >> "$FIX/sdk/typescript/src/client.ts"
    [[ "$(run_fixture)" != "0" ]] || { echo "FAIL: self-test absence — http://127.0.0.1 in the TS client ACCEPTED" >&2; exit 2; }
    echo "PASS: self-test absence — http://127.0.0.1 in an SDK source is REJECTED"

    write_clean
    printf '\nQuickstart: `baseUrl: "http://localhost:9077"`\n' >> "$FIX/sdk/typescript/README.md"
    [[ "$(run_fixture)" != "0" ]] || { echo "FAIL: self-test absence — http://localhost in a README quickstart ACCEPTED" >&2; exit 2; }
    echo "PASS: self-test absence — http://localhost in a README quickstart is REJECTED (this IS the #3782 defect)"

    # ---- PRESENCE half ----------------------------------------------
    # The load-bearing pairing: a tree whose scheme is entirely correct
    # but whose READMEs never tell the adopter about the CA still FAILS.
    write_clean
    printf '# ai-memory — Python SDK\n\nNo CA guidance here.\n' > "$FIX/sdk/python/README.md"
    [[ "$(run_fixture)" != "0" ]] || { echo "FAIL: self-test presence — python README without the CA section ACCEPTED" >&2; exit 2; }
    run_fixture_out | grep -q "has no \"Trust the daemon's CA\" section" || {
        echo "FAIL: self-test presence — missing section not named" >&2; exit 2; }
    echo "PASS: self-test presence — an all-https tree whose python README lacks the CA section is REJECTED"

    write_clean
    printf '# ai-memory — TypeScript SDK\n\nNo CA guidance here.\n' > "$FIX/sdk/typescript/README.md"
    [[ "$(run_fixture)" != "0" ]] || { echo "FAIL: self-test presence — TS README without the CA section ACCEPTED" >&2; exit 2; }
    echo "PASS: self-test presence — the same omission in the TypeScript README is REJECTED"

    write_clean
    printf "# ai-memory — Python SDK\n\n## Trust the daemon's CA\n\nSomehow.\n" > "$FIX/sdk/python/README.md"
    [[ "$(run_fixture)" != "0" ]] || { echo "FAIL: self-test presence — a STUB CA section (heading only) ACCEPTED" >&2; exit 2; }
    run_fixture_out | grep -q 'never names local-ca.pem' || {
        echo "FAIL: self-test presence — stub section not named as missing the CA file" >&2; exit 2; }
    echo "PASS: self-test presence — a heading-only STUB section is REJECTED (it must name local-ca.pem)"

    write_clean
    printf "# ai-memory — TypeScript SDK\n\n## Trust the daemon's CA\n\nThe CA is \`<key_dir>/tls/local-ca.pem\`.\n" \
        > "$FIX/sdk/typescript/README.md"
    [[ "$(run_fixture)" != "0" ]] || { echo "FAIL: self-test presence — CA file named without the client option ACCEPTED" >&2; exit 2; }
    run_fixture_out | grep -q 'not the client option that pins it' || {
        echo "FAIL: self-test presence — missing client option not named" >&2; exit 2; }
    echo "PASS: self-test presence — naming the CA file without the pinning option (caCert) is REJECTED"

    write_clean
    rm -f "$FIX/sdk/python/README.md"
    [[ "$(run_fixture)" != "0" ]] || { echo "FAIL: self-test presence — a MISSING README passed" >&2; exit 2; }
    echo "PASS: self-test presence — a missing SDK README FAILS CLOSED"

    # ---- fail CLOSED -------------------------------------------------
    write_clean
    fault_rc=0
    fault_out="$(AI_MEMORY_SDK_TLS_GATE_ROOT="$FIX" AI_MEMORY_SDK_TLS_GATE_SELFTEST_FAULT=1 "$SELF" 2>&1)" || fault_rc=$?
    [[ "$fault_rc" -ne 0 ]] || {
        echo "FAIL: self-test #2713 — the gate exited 0 on an injected scanner fault (fail-OPEN)" >&2; exit 2; }
    grep -q 'gate (#3782): PASS' <<<"$fault_out" && {
        echo "FAIL: self-test #2713 — the gate printed a PASS banner despite a scanner fault" >&2; exit 2; }
    echo "PASS: self-test #2713 — a scanner error FAILS CLOSED (exit $fault_rc, no PASS banner)"

    write_clean
    rm -rf "$FIX/sdk"
    mkdir -p "$FIX/sdk"
    [[ "$(run_fixture)" != "0" ]] || {
        echo "FAIL: self-test — an EMPTY sdk tree passed; the gate can no-op to green (#2444 shape)" >&2; exit 2; }
    echo "PASS: self-test — an empty sdk scan set fails CLOSED rather than reporting an unearned pass"

    echo "check-sdk-tls-scheme self-test OK"
    exit 0
fi

if [[ "${1:-}" != "" ]]; then
    printf 'usage: %s [--self-test]\n' "$(basename "${BASH_SOURCE[0]}")" >&2
    exit 2
fi

if [[ -n "${AI_MEMORY_SDK_TLS_GATE_ROOT:-}" ]]; then
    REPO_ROOT="$AI_MEMORY_SDK_TLS_GATE_ROOT"
else
    REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi

rc=0
run_gate "$REPO_ROOT" || rc=$?
exit "$rc"
