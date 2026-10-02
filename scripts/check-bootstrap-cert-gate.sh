#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# CERT GATE — Cluster-A cert-posture armability (#3061 #3016 #3067).
# Sibling to scripts/check-cert-removal-proof.sh: a LOAD-BEARING, end-to-end
# runtime proof driven through the COMPILED `ai-memory` binary (not a source
# grep), with plant-a-violation negative controls.
#
# It proves two properties the cluster exists to guarantee:
#
#   LEG A (#3061) — posture control #15 is BACKEND-AWARE and ARMABLE on a
#   postgres store. A fresh node in the certified pg config
#   (`sslmode=verify-full` DSN + AI_MEMORY_PG_AT_REST_ATTESTED=1) makes
#   `doctor --posture enterprise-federation` reach exit 0 — the whole point
#   of #3061 (pre-#3061 #15 was UNSATISFIABLE on pg, so the #17 boot gate
#   could never arm a pg node). NEGATIVE CONTROLS: dropping the attestation,
#   or weakening the DSN below verify-full, turns the gate RED. `doctor
#   --posture` never opens the DB, so this needs no live postgres.
#
#   LEG B (#3016/#3067) — a store-only-migrated node (empty `signed_events`
#   spine) is born DIRTY and only reaches CERTIFIED-READY through the single
#   idempotent `ai-memory audit bootstrap-node` command run under the FULL
#   certified asi-hard AUDIT require-mode set (witness + role + lineage all
#   armed) WITH the operator custody keys enrolled (witness + recorder). The
#   success label names EXACTLY which modes were armed (MB1). NEGATIVE
#   CONTROLS: asi-hard armed WITHOUT the custody keys REFUSES and names the
#   unmet ceremonies; certified modes NOT armed REFUSES to claim certified
#   even though the bare verify is clean (the false-green MB1 closes).
#
#   LEG A is certified in TWO separately named shapes (#4333 R4 / #4434): the
#   verify-full floor is only ever `Pinned` in a binary built WITH the
#   `sal-postgres` driver (a driverless binary can never certify a pg posture,
#   by design — fail-closed), so a single run on one binary cannot cover both.
#     LEG A-pg         — `sal,sal-postgres` binary: certified pg config exits 0,
#                        negative controls exit 2.
#     LEG A-driverless — binary WITHOUT `sal-postgres`: the SAME config must
#                        REFUSE (exit 2) and the failing posture ROW must be
#                        AI_MEMORY_PG_AT_REST_ATTESTED (the row is asserted,
#                        not merely a non-zero code).
#   Each leg must print RUN; the gate FAILS if either did not run. Each binary
#   is NON-VACUITY-probed through its own feature surface
#   (`AI_MEMORY_NO_CONFIG=1 <bin> features --json`, parsed — never prose
#   grep): A-pg's binary MUST list `sal-postgres`, A-driverless's MUST NOT. A
#   missing / erroring / unparseable probe, or a swapped binary, is exit 3 with
#   an INSTRUMENT ERROR naming #4434 and #2676.
#
# USAGE:
#   scripts/check-bootstrap-cert-gate.sh          # self-build both binaries + run
#   AI_MEMORY_BIN_PG=/path/to/pg-binary \          # sal,sal-postgres build
#   AI_MEMORY_BIN=/path/to/driverless-binary \     # build lacking sal-postgres
#     scripts/check-bootstrap-cert-gate.sh
#   scripts/check-bootstrap-cert-gate.sh --self-test   # stub-binary proof that
#                                                      # the instrument fails closed
#
# Exit: 0 PASS; 1 a leg assertion failed; 3 INSTRUMENT ERROR (bad/missing/
# swapped binary or probe, build failure).
set -uo pipefail

# #3117 — normalise to the STANDARD umask before creating ANY key directory.
# LEG A / LEG B mint throwaway Ed25519 keypairs into `mkdir -p` directories
# (KEYDIR_A, KEYDIR_B, WDIR_B, RDIR_B, the empty witness/recorder dirs,
# KEYDIR_D/E). The #3198 whole-chain key-dir gate
# (`identity::keypair::enforce_key_dir_secure`, `KEY_DIR_FORBIDDEN_BITS=0o022`)
# REFUSES a group- or world-WRITABLE key directory: a second local UID could
# swap in an attacker-controlled matched `.priv`/`.pub` pair. That gate is
# deliberately tuned to ACCEPT a default-`umask 022` tree (mode 0755, readable
# but not writable) and REFUSE only the write bits. The self-hosted
# `linux-fed` cert runner (this fleet) runs `umask 0002`, so a bare `mkdir -p`
# is born 0775 — group-writable — and every `identity generate` refuses with
# "key directory … is group- or world-writable (mode 775)". That aborted LEG
# A at "could not mint an R40 approver pubkey" (exit 3) BEFORE `doctor
# --posture` ever ran, reding the cert gate. Forcing `umask 022` here makes
# every directory this script creates born 0755 — the exact mode #3198 was
# built to accept — with no other behavioural change (it is stricter than the
# fleet default, never looser). Keeps the fix in the harness, not in the
# production keystore posture, which is correct as-is.
umask 022


# ── mode flags ──────────────────────────────────────────────────────────────
# --self-test   stub-binary proof of the instrument (never touches real bins)
# --probe-only  hidden: stop after the feature-surface probes (self-test hook)
# --leg-a-only  hidden: run LEG A-pg + A-driverless, skip LEG B (self-test hook)
SELF_TEST=0; PROBE_ONLY=0; LEG_A_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --self-test) SELF_TEST=1 ;;
    --probe-only) PROBE_ONLY=1 ;;
    --leg-a-only) LEG_A_ONLY=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 3 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SELF="$REPO_ROOT/scripts/$(basename "${BASH_SOURCE[0]}")"
cd "$REPO_ROOT"

python3 -c 'import json,sys' 2>/dev/null \
  || { echo "INSTRUMENT ERROR: python3 is required to parse the feature probe and posture rows (#4434 #2676)"; exit 3; }

# ── --self-test: STUB binaries only, writes only inside its own temp dir ────
if [[ $SELF_TEST -eq 1 ]]; then
  ST="$(mktemp -d)"
  trap 'rm -rf "$ST"' EXIT
  ST_FAIL=0
  git_state() { git -C "$REPO_ROOT" status --porcelain 2>/dev/null | sha256sum; }
  TREE_BEFORE="$(git_state)"

  # mkstub <path> <features-json-body | RAW:<text> | ERR> <doctor-mode> <row-control>
  #   doctor-mode: pgsim  = refuse unless attested AND sslmode=verify-full
  #                fixed2 = always exit 2 failing <row-control>
  #                zero   = always exit 0 (a driverless binary that certifies)
  mkstub() {
    local path="$1" feat="$2" mode="$3" row="$4"
    {
      echo '#!/usr/bin/env bash'
      echo 'case "$1" in'
      echo '  features)'
      case "$feat" in
        ERR) echo '    echo "stub: features probe unavailable" >&2; exit 1 ;;' ;;
        RAW:*) printf '    printf %%s %q; exit 0 ;;\n' "${feat#RAW:}" ;;
        *) printf '    printf %%s %q; exit 0 ;;\n' "$feat" ;;
      esac
      echo '  identity) case "$2" in export-pub) echo "AAAAstubpubkey";; esac; exit 0 ;;'
      echo '  doctor)'
      echo '    row() { printf "{\n  \"checks\": [\n    {\n      \"control\": \"%s\",\n      \"required\": \"r\",\n      \"actual\": \"a\",\n      \"pass\": %s,\n      \"remediation\": \"x\"\n    }\n  ]\n}\n" "$1" "$2"; }'
      case "$mode" in
        pgsim)
          echo '    if [[ -n "${AI_MEMORY_PG_AT_REST_ATTESTED:-}" && "${AI_MEMORY_STORE_URL:-}" == *sslmode=verify-full* && -n "${AI_MEMORY_APPROVER_PUBKEYS:-}" ]]; then'
          echo '      row "AI_MEMORY_PG_AT_REST_ATTESTED (postgres at-rest, COMPENSATING control)" true; exit 0'
          echo '    fi'
          echo '    row "AI_MEMORY_PG_AT_REST_ATTESTED (postgres at-rest, COMPENSATING control)" false; exit 2 ;;'
          ;;
        fixed2) printf '    row %q false; exit 2 ;;\n' "$row" ;;
        zero)   printf '    row %q true; exit 0 ;;\n' "$row" ;;
      esac
      echo '  *) exit 0 ;;'
      echo 'esac'
    } > "$path"
    chmod +x "$path"
  }

  F_PG='{"version":"1.0.0","features":["sal","sal-postgres","sqlite-bundled"]}'
  F_ND='{"version":"1.0.0","features":["sal","sqlite-bundled"]}'
  ROW_ATT='AI_MEMORY_PG_AT_REST_ATTESTED (postgres at-rest, COMPENSATING control)'
  ROW_OTHER='AI_MEMORY_SOMETHING_ELSE (unrelated posture failure)'

  # st_case <name> <expected-rc> <expected-text-or-""> <pg-stub> <nd-stub>
  st_case() {
    local name="$1" want="$2" text="$3" pgb="$4" ndb="$5" out rc
    out="$(env TMPDIR="$ST" AI_MEMORY_CERT_EVIDENCE_DIR="$ST/evidence" \
        AI_MEMORY_BIN_PG="$pgb" AI_MEMORY_BIN="$ndb" \
        bash "$SELF" --leg-a-only 2>&1)"
    rc=$?
    if [[ $rc -eq $want ]] && { [[ -z "$text" ]] || grep -qF -- "$text" <<<"$out"; }; then
      echo "[ST-OK]   $name: gate exit $rc (expected $want)${text:+, saw '$text'}"
    else
      echo "[ST-FAIL] $name: gate exit $rc (expected $want${text:+, text '$text'})"
      sed 's/^/      | /' <<<"$out" | head -12
      ST_FAIL=1
    fi
  }

  mkdir -p "$ST/evidence"
  mkstub "$ST/pg-good"   "$F_PG" pgsim  "$ROW_ATT"
  mkstub "$ST/nd-good"   "$F_ND" fixed2 "$ROW_ATT"
  mkstub "$ST/pg-nodrv"  "$F_ND" pgsim  "$ROW_ATT"
  mkstub "$ST/nd-hasdrv" "$F_PG" fixed2 "$ROW_ATT"
  mkstub "$ST/bin-garble" "RAW:this is not json {" fixed2 "$ROW_ATT"
  mkstub "$ST/bin-nokey"  '{"version":"1.0.0"}' fixed2 "$ROW_ATT"
  mkstub "$ST/bin-noprobe" ERR fixed2 "$ROW_ATT"
  mkstub "$ST/nd-wrongrow" "$F_ND" fixed2 "$ROW_OTHER"
  mkstub "$ST/nd-certifies" "$F_ND" zero "$ROW_ATT"
  mkstub "$ST/pg-refuses" "$F_PG" fixed2 "$ROW_ATT"

  echo "== --self-test: stub binaries, canned 'features --json' =="
  st_case "positive control (right binaries)"          0 "CERT-BOOTSTRAP GATE: PASS" "$ST/pg-good" "$ST/nd-good"
  st_case "A-pg binary WITHOUT sal-postgres"           3 "INSTRUMENT ERROR"          "$ST/pg-nodrv" "$ST/nd-good"
  st_case "A-driverless binary WITH sal-postgres"      3 "INSTRUMENT ERROR"          "$ST/pg-good" "$ST/nd-hasdrv"
  st_case "SWAPPED binaries"                           3 "INSTRUMENT ERROR"          "$ST/nd-good" "$ST/pg-good"
  st_case "A-pg probe unparseable"                     3 "#2676"                     "$ST/bin-garble" "$ST/nd-good"
  st_case "A-driverless probe unparseable"             3 "#2676"                     "$ST/pg-good" "$ST/bin-garble"
  st_case "probe JSON lacks features key"              3 "#4434"                     "$ST/bin-nokey" "$ST/nd-good"
  st_case "A-pg probe missing (binary errors)"         3 "INSTRUMENT ERROR"          "$ST/bin-noprobe" "$ST/nd-good"
  st_case "A-driverless probe missing (binary errors)" 3 "INSTRUMENT ERROR"          "$ST/pg-good" "$ST/bin-noprobe"
  st_case "A-pg binary not executable / absent"        3 "INSTRUMENT ERROR"          "$ST/does-not-exist" "$ST/nd-good"
  st_case "driverless refuses on the WRONG row"        1 "[FAIL]"                    "$ST/pg-good" "$ST/nd-wrongrow"
  st_case "driverless binary certifies (exit 0)"       1 "[FAIL]"                    "$ST/pg-good" "$ST/nd-certifies"
  st_case "A-pg certified config does not reach 0"     1 "[FAIL]"                    "$ST/pg-refuses" "$ST/nd-good"

  TREE_AFTER="$(git_state)"
  if [[ "$TREE_BEFORE" == "$TREE_AFTER" ]]; then
    echo "[ST-OK]   self-test left the working tree untouched"
  else
    echo "[ST-FAIL] self-test changed the working tree"; ST_FAIL=1
  fi
  if [[ $ST_FAIL -eq 0 ]]; then echo "CERT-BOOTSTRAP GATE SELF-TEST: PASS"; exit 0; fi
  echo "CERT-BOOTSTRAP GATE SELF-TEST: FAIL"; exit 1
fi

# Absolute so the `cd "$WORK_B"` bring-up subshells below still resolve it.
EVIDENCE_DIR="${AI_MEMORY_CERT_EVIDENCE_DIR:-$REPO_ROOT/.local-runs/cert-bootstrap-evidence}"
mkdir -p "$EVIDENCE_DIR"

FAILED=0
note() { printf '  %s\n' "$*"; }
pass() { printf '[PASS] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*"; FAILED=1; }
instrument_error() {
  echo "INSTRUMENT ERROR: $*" >&2
  echo "  (#4434: a driverless binary can never certify a pg posture; #2676: 'features --json' is the probe)" >&2
  exit 3
}

# ── locate / build the TWO binaries ────────────────────────────────────────
# A-pg needs `sal,sal-postgres`; A-driverless needs a binary lacking
# `sal-postgres`. Separate target dirs so the two builds never clobber each
# other's target/debug/ai-memory.
BIN_PG="${AI_MEMORY_BIN_PG:-}"
if [[ -z "$BIN_PG" ]]; then
  echo "building ai-memory (--features sal,sal-postgres) for LEG A-pg…"
  cargo build --quiet --bin ai-memory --features sal,sal-postgres \
    --target-dir "$REPO_ROOT/target/cert-gate-pg" || { echo "build failed (A-pg)"; exit 3; }
  BIN_PG="$REPO_ROOT/target/cert-gate-pg/debug/ai-memory"
fi
BIN_ND="${AI_MEMORY_BIN:-}"
if [[ -z "$BIN_ND" ]]; then
  echo "building ai-memory (default features, no sal-postgres) for LEG A-driverless…"
  cargo build --quiet --bin ai-memory \
    --target-dir "$REPO_ROOT/target/cert-gate-driverless" || { echo "build failed (A-driverless)"; exit 3; }
  BIN_ND="$REPO_ROOT/target/cert-gate-driverless/debug/ai-memory"
fi
[[ -x "$BIN_PG" ]] || { echo "INSTRUMENT ERROR: A-pg binary not executable: $BIN_PG" >&2; exit 3; }
[[ -x "$BIN_ND" ]] || { echo "INSTRUMENT ERROR: A-driverless binary not executable: $BIN_ND" >&2; exit 3; }
echo "A-pg binary:         $BIN_PG"
echo "A-driverless binary: $BIN_ND"

# NON-VACUITY: positive, PARSED probe of the binary's own feature surface.
# Prints one feature per line; any failure to obtain a well-formed list is an
# INSTRUMENT ERROR (never a silent pass).
probe_features() {
  local bin="$1" raw
  raw="$(AI_MEMORY_NO_CONFIG=1 "$bin" features --json 2>/dev/null)" \
    || instrument_error "'$bin features --json' failed (probe missing/erroring)"
  printf '%s' "$raw" | python3 -c '
import json, sys
d = json.load(sys.stdin)
f = d["features"]
if not isinstance(f, list) or not all(isinstance(x, str) for x in f):
    raise SystemExit(1)
print("\n".join(f))
' 2>/dev/null || instrument_error "'$bin features --json' output is unparseable or lacks a features list"
}
FEATS_PG="$(probe_features "$BIN_PG")" || exit $?
FEATS_ND="$(probe_features "$BIN_ND")" || exit $?
has_feature() { grep -qxF -- "$2" <<<"$1"; }
has_feature "$FEATS_PG" sal-postgres \
  || instrument_error "A-pg binary '$BIN_PG' lacks the sal-postgres feature (features: $(tr '\n' ' ' <<<"$FEATS_PG"))"
! has_feature "$FEATS_ND" sal-postgres \
  || instrument_error "A-driverless binary '$BIN_ND' HAS the sal-postgres feature (swapped/mis-supplied binaries?)"
echo "probe ok: A-pg features = [$(tr '\n' ' ' <<<"$FEATS_PG")]; A-driverless features = [$(tr '\n' ' ' <<<"$FEATS_ND")]"
[[ $PROBE_ONLY -eq 1 ]] && { echo "probe-only: OK"; exit 0; }

# A postgres DSN never connected (doctor --posture is env-only): the query
# string is all that #15 machine-checks.
PG_DSN_VERIFY_FULL="postgres://u@db.internal:5432/mem?sslmode=verify-full"
PG_DSN_REQUIRE_ONLY="postgres://u@db.internal:5432/mem?sslmode=require"

# Failing posture rows (control names), one per line, parsed from the JSON.
failing_rows() {
  python3 -c '
import json, sys
def walk(x):
    if isinstance(x, dict):
        if "control" in x and x.get("pass") is False:
            print(x["control"])
        for v in x.values(): walk(v)
    elif isinstance(x, list):
        for v in x: walk(v)
try:
    walk(json.load(open(sys.argv[1])))
except Exception:
    raise SystemExit(1)
' "$1"
}

# ── LEG A — #3061 backend-aware #15, pg armability ─────────────────────────
# Shared certified env for a pg backend. asi-hard auto-pins the knobs in
# the binary's pre-runtime phase (src/main.rs); the rest are the federation
# additions the posture requires. A fingerprints file + attestation JSON +
# trust domain satisfy checks #9/#10/#11/#12; append-only + a daemon audit
# signing key satisfy #19.
# HERMETIC key dir: a fresh PRIVATE parent, not bare $TMPDIR. `enrolled_
# approver_keys` -> `resolve_operator_pubkey` walks BOTH the key dir and its
# PARENT for an on-disk `operator.key.pub`, so a shared /tmp could otherwise
# make the keyless negative control below silently un-negative on a dev host.
# leg_a_setup <bin> — mints the hermetic key material with THAT leg's binary.
leg_a_setup() {
  local bin="$1"
  WORK_A="$(mktemp -d)"
  KEYDIR_A="$WORK_A/keys"
  mkdir -p "$KEYDIR_A"
  FPFILE_A="$(mktemp)"
  printf 'example.org 0000000000000000000000000000000000000000000000000000000000000000\n' > "$FPFILE_A"
  # The daemon audit signing key for check #19 (resolve_agent_id honours
  # AI_MEMORY_AGENT_ID); generate it into the key dir.
  AGENT_A="cert-node-3061"
  env AI_MEMORY_KEY_DIR="$KEYDIR_A" AI_MEMORY_AGENT_ID="$AGENT_A" \
    "$bin" identity generate --agent-id "$AGENT_A" >/dev/null 2>&1 || true
  # #2991 check #20 — the certified config MUST enroll at least one R40
  # approver key so the wired L1-6 escalate producer routes to a SATISFIABLE
  # signed-approval gate (keyless, the producer's fail-closed guardrail would
  # block escalated writes forever). Mint a REAL Ed25519 key with the SAME
  # binary and enroll its pubkey — never a hardcoded literal.
  local approver="cert-approver-2991"
  "$bin" identity generate --agent-id "$approver" --key-dir "$KEYDIR_A" \
    >/dev/null 2>&1 || true
  APPROVER_PUBKEY_A="$("$bin" identity export-pub --agent-id "$approver" \
    --key-dir "$KEYDIR_A" 2>/dev/null)"
  [[ -n "$APPROVER_PUBKEY_A" ]] || { echo "could not mint an R40 approver pubkey"; exit 3; }
}

# posture_env <bin> <attest "1"|""> <dsn> [approver-assignment override]
#   $4 = OPTIONAL override of the R40 approver enrollment assignment; pass ""
#        to strip it entirely (the #2991 check-#20 negative control).
posture_env() {
  local bin="$1"
  env \
    AI_MEMORY_SECURITY_PROFILE=asi-hard \
    AI_MEMORY_FED_TRUST_DOMAIN=test-fleet \
    AI_MEMORY_FED_PEER_FINGERPRINTS="$FPFILE_A" \
    AI_MEMORY_FED_PEER_ATTESTATION='{"peer-1":{"allowed_namespaces":["public/*"]}}' \
    AI_MEMORY_STORE_URL="$3" \
    ${2:+AI_MEMORY_PG_AT_REST_ATTESTED=$2} \
    AI_MEMORY_APPEND_ONLY=1 \
    AI_MEMORY_KEY_DIR="$KEYDIR_A" \
    AI_MEMORY_AGENT_ID="$AGENT_A" \
    ${4-AI_MEMORY_APPROVER_PUBKEYS=$APPROVER_PUBKEY_A} \
    AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE=1 \
    "$bin" doctor --posture enterprise-federation --json
}

RAN_A_PG=0
RAN_A_DRIVERLESS=0

# ── LEG A-pg — sal,sal-postgres binary: certify (exit 0) + negative controls
echo
echo "== LEG A-pg — #3061 pg posture armability (binary WITH sal-postgres) =="
echo "LEG A-pg: RUN"
RAN_A_PG=1
leg_a_setup "$BIN_PG"

# Certified pg config → doctor --posture exits 0, and #15 is the pg
# compensating control (NOT the sqlcipher predicate).
OUT_A="$EVIDENCE_DIR/pg-posture-pass.json"
ERR_A="$EVIDENCE_DIR/pg-posture-pass.err"
posture_env "$BIN_PG" 1 "$PG_DSN_VERIFY_FULL" > "$OUT_A" 2>"$ERR_A"
CODE_A=$?
if [[ $CODE_A -eq 0 ]]; then
  pass "fresh pg node in the certified config: doctor --posture exit 0 (#3061 armable)"
else
  fail "certified pg config did NOT reach exit 0 (got $CODE_A) — see $OUT_A"
  # Failing rows are parsed from the JSON (never grepped). stderr is echoed
  # too: a NON-doctor exit (e.g. a boot refusal) writes there and leaves the
  # JSON file empty, and that distinction is the whole diagnosis.
  failing_rows "$OUT_A" 2>/dev/null | sed 's/^/    FAIL-ROW /' || true
  sed 's/^/    STDERR /' "$ERR_A" 2>/dev/null | head -20 || true
fi
# Both halves match the "control" FIELD (not any occurrence of the name in a
# required/actual/remediation string), and tolerate compact OR pretty JSON —
# `run_posture --json` emits `to_string_pretty`, so the pre-existing
# compact-only spelling of the NEGATIVE half could never match and the "not
# the sqlcipher predicate" clause was vacuously true.
CONTROL_FIELD_RE='"control": *"'
if grep -qE "${CONTROL_FIELD_RE}AI_MEMORY_PG_AT_REST_ATTESTED" "$OUT_A" 2>/dev/null \
   && ! grep -qE "${CONTROL_FIELD_RE}AI_MEMORY_ENCRYPT_AT_REST\"" "$OUT_A" 2>/dev/null; then
  pass "control #15 is the pg COMPENSATING control, not the sqlcipher predicate"
else
  fail "control #15 did not resolve to the pg compensating control on a postgres DSN"
fi

# NEGATIVE CONTROL 1 — drop the operator attestation → gate must refuse with
# exit 2 (the posture refusal code), not merely any non-zero.
posture_env "$BIN_PG" "" "$PG_DSN_VERIFY_FULL" > "$EVIDENCE_DIR/pg-posture-no-attest.json" 2>/dev/null
RC=$?
if [[ $RC -eq 2 ]]; then
  pass "negative control: verify-full WITHOUT AI_MEMORY_PG_AT_REST_ATTESTED refuses (exit 2)"
else
  fail "the pg at-rest attestation is NOT load-bearing — posture exit $RC without it (expected 2)"
fi

# NEGATIVE CONTROL 2 — weaken the DSN below verify-full → gate must refuse (exit 2).
posture_env "$BIN_PG" 1 "$PG_DSN_REQUIRE_ONLY" > "$EVIDENCE_DIR/pg-posture-weak-tls.json" 2>/dev/null
RC=$?
if [[ $RC -eq 2 ]]; then
  pass "negative control: sslmode=require (not verify-full) + attestation refuses (exit 2)"
else
  fail "the sslmode=verify-full TLS half is NOT load-bearing — posture exit $RC (expected 2)"
fi

# NEGATIVE CONTROL 3 (#2991 check #20) — strip the R40 approver enrollment
# from the otherwise-certified config → gate goes RED. Proves the newly
# required enrollment is LOAD-BEARING, not decorative, and pins the certified
# config's #2991 half so a future control addition cannot silently drift the
# gate's notion of "the certified pg config" again.
posture_env "$BIN_PG" 1 "$PG_DSN_VERIFY_FULL" "" > "$EVIDENCE_DIR/pg-posture-no-approver.json" 2>/dev/null
RC=$?
if [[ $RC -eq 2 ]]; then
  pass "negative control: certified pg config WITHOUT an enrolled R40 approver key refuses (exit 2)"
else
  fail "the #2991 approver-key enrollment is NOT load-bearing — posture exit $RC (expected 2)"
fi
rm -rf "$WORK_A" "$FPFILE_A"

# ── LEG A-driverless — binary WITHOUT sal-postgres: must REFUSE, on the ROW ─
echo
echo "== LEG A-driverless — #4333/#4434 driverless binary must REFUSE a pg posture =="
echo "LEG A-driverless: RUN"
RAN_A_DRIVERLESS=1
leg_a_setup "$BIN_ND"
OUT_D="$EVIDENCE_DIR/driverless-posture-refuse.json"
posture_env "$BIN_ND" 1 "$PG_DSN_VERIFY_FULL" > "$OUT_D" 2>"$EVIDENCE_DIR/driverless-posture-refuse.err"
RC=$?
ROWS_D="$(failing_rows "$OUT_D" 2>/dev/null)"
if [[ $RC -eq 2 ]] && grep -qE '^AI_MEMORY_PG_AT_REST_ATTESTED( |$)' <<<"$ROWS_D"; then
  pass "driverless binary REFUSES the certified pg config: exit 2, FAIL-ROW AI_MEMORY_PG_AT_REST_ATTESTED (#4333 R4 fail-closed)"
else
  fail "driverless binary did not refuse on AI_MEMORY_PG_AT_REST_ATTESTED (exit $RC; failing rows: ${ROWS_D:-none parsed}) — see $OUT_D"
  sed 's/^/    FAIL-ROW /' <<<"$ROWS_D"
fi
rm -rf "$WORK_A" "$FPFILE_A"

if [[ $RAN_A_PG -ne 1 || $RAN_A_DRIVERLESS -ne 1 ]]; then
  fail "a LEG A shape did not RUN (A-pg=$RAN_A_PG A-driverless=$RAN_A_DRIVERLESS) — a skipped leg is never green"
fi

if [[ $LEG_A_ONLY -eq 1 ]]; then
  echo
  if [[ $FAILED -eq 0 ]]; then echo "CERT-BOOTSTRAP GATE: PASS"; exit 0; fi
  echo "CERT-BOOTSTRAP GATE: FAIL"; exit 1
fi

# LEG B is sqlite-only; run it with the superset (pg) binary.
BIN="$BIN_PG"

# ── LEG B — #3016/#3067 born-dirty → mechanical bring-up (asi-hard) ─────────
echo
echo "== LEG B — #3016/#3067 born-dirty bring-up gate (certified asi-hard modes) =="

WORK_B="$(mktemp -d)"
KEYDIR_B="$WORK_B/keys"; WDIR_B="$WORK_B/witness"; RDIR_B="$WORK_B/recorder"
EMPTY_W="$WORK_B/empty-witness"; EMPTY_R="$WORK_B/empty-recorder"
mkdir -p "$KEYDIR_B" "$WDIR_B" "$RDIR_B" "$EMPTY_W" "$EMPTY_R"
AGENT_B="cert-node-3016"

# The certified verdict is gated on the FULL asi-hard AUDIT require-mode set
# (MB1): bootstrap-node reports CERTIFIED-READY only when witness + role +
# lineage are ALL armed AND the verify is clean under them.
CERT_MODES=(AI_MEMORY_REQUIRE_WITNESS=1 AI_MEMORY_REQUIRE_ROLE_SEPARATION=1 AI_MEMORY_REQUIRE_IDENTITY_LINEAGE=1)

# HERMETIC db resolution (DATA-INTEGRITY CRITICAL). The `audit` subcommand
# resolves its db from `AppConfig` (config.toml `db`), NOT the cwd, so a stray
# `~/.config/ai-memory/config.toml` would point bring-up at a REAL operator DB.
# `AI_MEMORY_NO_CONFIG=1` skips config loading so `effective_db` falls to the
# cwd-relative default (`./ai-memory.db` in $WORK_B); `AI_MEMORY_STORE_URL` /
# `_FILE` are cleared so no external store is opened.
am_b() { ( cd "$WORK_B" && env AI_MEMORY_NO_CONFIG=1 AI_MEMORY_STORE_URL= AI_MEMORY_STORE_URL_FILE= "$@" ); }

# Store-only-migrated node: registry populated, spine empty. Enroll the
# operator custody keys bring-up VERIFIES (never mints): witness + recorder.
# NOT judge — a judge pubkey needs a verdict checkpoint no fresh-node CLI mints
# (recorder-only is the correct fresh-node role-separation posture).
am_b "$BIN" identity generate --agent-id "$AGENT_B" --key-dir "$KEYDIR_B" >/dev/null 2>&1
am_b "$BIN" identity generate --agent-id "${AGENT_B}-recovery" --key-dir "$KEYDIR_B" >/dev/null 2>&1
RECOVERY_B="$(am_b "$BIN" identity export-pub --agent-id "${AGENT_B}-recovery" --key-dir "$KEYDIR_B" 2>/dev/null)"
"$BIN" identity generate --agent-id audit-witness --key-dir "$WDIR_B" >/dev/null 2>&1
"$BIN" identity generate --agent-id governance-recorder --key-dir "$RDIR_B" >/dev/null 2>&1
am_b "$BIN" agents register --agent-id "$AGENT_B" --agent-type ai:test >/dev/null 2>&1

# BORN DIRTY — under an armed audit require-mode, the empty spine convicts.
am_b env AI_MEMORY_REQUIRE_IDENTITY_LINEAGE=1 "$BIN" verify-audit-trail >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
  pass "store-only-migrated node (empty spine) is BORN DIRTY under armed require-lineage (exit != 0)"
else
  fail "an empty spine passed verify-audit-trail under armed require-lineage — NOT born dirty"
fi

# CERTIFIED — under the FULL asi-hard modes WITH witness + recorder keys.
am_b env "${CERT_MODES[@]}" AI_MEMORY_WITNESS_KEY_DIR="$WDIR_B" AI_MEMORY_RECORDER_KEY_DIR="$RDIR_B" \
    "$BIN" audit bootstrap-node --agent-id "$AGENT_B" --key-dir "$KEYDIR_B" \
    --recovery-pubkey "$RECOVERY_B" > "$EVIDENCE_DIR/bring-up.out" 2>&1
BRINGUP_CODE=$?
# Defense-in-depth: PROVE bring-up wrote ONLY the sandbox db, never a real one.
if grep -qE "db: +(\./)?ai-memory\.db" "$EVIDENCE_DIR/bring-up.out" \
   || grep -qF "db:              $WORK_B" "$EVIDENCE_DIR/bring-up.out"; then
  pass "bring-up resolved the SANDBOX db (hermetic — never a config/operator DB)"
else
  fail "bring-up did NOT resolve the sandbox db — refusing to trust the result"
  grep -E "^  db:" "$EVIDENCE_DIR/bring-up.out" | sed 's/^/    /'
fi
if [[ $BRINGUP_CODE -eq 0 ]] && grep -q "CERTIFIED-READY" "$EVIDENCE_DIR/bring-up.out"; then
  pass "audit bootstrap-node CERTIFIED under full asi-hard modes with witness+recorder keys (exit 0)"
else
  fail "bootstrap-node did not certify under asi-hard — see $EVIDENCE_DIR/bring-up.out"
fi
# The success label must NAME the armed modes for the auditor (MB1).
if grep -qE "CERTIFIED-READY.*witness.*role_separation.*identity_lineage" "$EVIDENCE_DIR/bring-up.out"; then
  pass "CERTIFIED-READY names EXACTLY the armed require-modes for the verdict"
else
  fail "CERTIFIED-READY must name the armed modes (auditor seam) — see bring-up.out"
fi

# CLEAN AFTER — verify now exits 0 under the same armed modes.
am_b env "${CERT_MODES[@]}" AI_MEMORY_WITNESS_KEY_DIR="$WDIR_B" AI_MEMORY_RECORDER_KEY_DIR="$RDIR_B" \
    "$BIN" verify-audit-trail >/dev/null 2>&1
if [[ $? -eq 0 ]]; then
  pass "after bring-up, verify-audit-trail exits 0 under the certified modes"
else
  fail "verify-audit-trail still dirty after bring-up under the certified modes"
fi

# IDEMPOTENT — re-run with NO recovery pubkey stays exit 0.
am_b env "${CERT_MODES[@]}" AI_MEMORY_WITNESS_KEY_DIR="$WDIR_B" AI_MEMORY_RECORDER_KEY_DIR="$RDIR_B" \
    "$BIN" audit bootstrap-node --agent-id "$AGENT_B" --key-dir "$KEYDIR_B" >/dev/null 2>&1
if [[ $? -eq 0 ]]; then
  pass "bootstrap-node is idempotent: re-run without --recovery-pubkey stays certified"
else
  fail "bootstrap-node re-run was not idempotent"
fi

# NEGATIVE CONTROL 1 (MB1 core) — asi-hard modes armed but NO custody keys
# (empty dirs) MUST refuse and name the unmet ceremonies. A FRESH node.
WORK_D="$(mktemp -d)"; KEYDIR_D="$WORK_D/keys"; mkdir -p "$KEYDIR_D"
am_d() { ( cd "$WORK_D" && env AI_MEMORY_NO_CONFIG=1 AI_MEMORY_STORE_URL= AI_MEMORY_STORE_URL_FILE= "$@" ); }
am_d "$BIN" identity generate --agent-id nokeys-node --key-dir "$KEYDIR_D" >/dev/null 2>&1
am_d "$BIN" identity generate --agent-id nokeys-recovery --key-dir "$KEYDIR_D" >/dev/null 2>&1
REC_D="$(am_d "$BIN" identity export-pub --agent-id nokeys-recovery --key-dir "$KEYDIR_D" 2>/dev/null)"
am_d "$BIN" agents register --agent-id nokeys-node --agent-type ai:test >/dev/null 2>&1
am_d env "${CERT_MODES[@]}" AI_MEMORY_WITNESS_KEY_DIR="$EMPTY_W" AI_MEMORY_RECORDER_KEY_DIR="$EMPTY_R" \
    AI_MEMORY_WITNESS_PUBKEY= AI_MEMORY_RECORDER_PUBKEY= \
    "$BIN" audit bootstrap-node --agent-id nokeys-node --key-dir "$KEYDIR_D" \
    --recovery-pubkey "$REC_D" > "$EVIDENCE_DIR/refuse-no-keys.out" 2>&1
if [[ $? -eq 1 ]] && grep -q "NOT CERTIFIED" "$EVIDENCE_DIR/refuse-no-keys.out" \
   && grep -q "WITNESS" "$EVIDENCE_DIR/refuse-no-keys.out" \
   && grep -q "ROLE SEPARATION" "$EVIDENCE_DIR/refuse-no-keys.out"; then
  pass "negative control: asi-hard armed WITHOUT custody keys REFUSES and names witness + role"
else
  fail "asi-hard without keys did NOT fail-close correctly — see $EVIDENCE_DIR/refuse-no-keys.out"
fi

# NEGATIVE CONTROL 2 (MB1 core) — certified modes NOT armed MUST refuse to claim
# certified even though the bare verify would be clean. A FRESH node.
WORK_E="$(mktemp -d)"; KEYDIR_E="$WORK_E/keys"; mkdir -p "$KEYDIR_E"
am_e() { ( cd "$WORK_E" && env AI_MEMORY_NO_CONFIG=1 AI_MEMORY_STORE_URL= AI_MEMORY_STORE_URL_FILE= \
    AI_MEMORY_REQUIRE_WITNESS= AI_MEMORY_REQUIRE_ROLE_SEPARATION= AI_MEMORY_REQUIRE_IDENTITY_LINEAGE= "$@" ); }
am_e "$BIN" identity generate --agent-id unarmed-node --key-dir "$KEYDIR_E" >/dev/null 2>&1
am_e "$BIN" identity generate --agent-id unarmed-recovery --key-dir "$KEYDIR_E" >/dev/null 2>&1
REC_E="$(am_e "$BIN" identity export-pub --agent-id unarmed-recovery --key-dir "$KEYDIR_E" 2>/dev/null)"
am_e "$BIN" agents register --agent-id unarmed-node --agent-type ai:test >/dev/null 2>&1
am_e "$BIN" audit bootstrap-node --agent-id unarmed-node --key-dir "$KEYDIR_E" \
    --recovery-pubkey "$REC_E" > "$EVIDENCE_DIR/refuse-unarmed.out" 2>&1
if [[ $? -eq 1 ]] && grep -q "require-modes are NOT all armed" "$EVIDENCE_DIR/refuse-unarmed.out"; then
  pass "negative control: certified modes NOT armed REFUSES the certified claim (no false-green)"
else
  fail "unarmed certified modes did NOT refuse — see $EVIDENCE_DIR/refuse-unarmed.out"
fi

rm -rf "$WORK_B" "$WORK_D" "$WORK_E"

echo
if [[ $FAILED -eq 0 ]]; then
  echo "CERT-BOOTSTRAP GATE: PASS"
  exit 0
fi
echo "CERT-BOOTSTRAP GATE: FAIL"
exit 1
