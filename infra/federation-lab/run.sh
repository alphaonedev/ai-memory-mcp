#!/usr/bin/env bash
# =============================================================================
# infra/federation-lab/run.sh — the ai-memory v1.0.0 laptop federation lab.
# =============================================================================
# ONE command stands up a two-node ai-memory federation on your laptop with
# mutual TLS, fingerprint-pinned peers, required agent attestation and every
# `asi-hard` posture knob at its hard floor; loads a sample of the
# synthetic corpus; and then PROVES the thing works by asserting both positives
# (an attested write replicates across the mesh and is recallable at the
# peer) and negatives (an unpinned client, a plaintext client and an unsigned
# write are all refused).
#
#     ./run.sh
#
# It is idempotent (each run wipes and rebuilds `run/`), it writes NOTHING
# outside this directory — no /tmp, no $HOME — and it stops every daemon it
# started on the way out, including on Ctrl-C.
#
# EXTENDS, DOES NOT FORK. All cryptographic material comes from the
# battle-tested `infra/do-hive/crypto/gen-certs.sh`, which this script CALLS.
# The federation topology and the pos/neg shapes follow its siblings
# `test-federation-mtls.sh` and `test-fed-write-sig-attestation.sh`. Their
# comments encode fixes (#1842, #2293, the RSA-not-Ed25519 requirement, the
# boot-race poll window) that are preserved here rather than rediscovered.
#
# HONESTY. Read README.md §"What this does and does not prove". In short:
# this is a functional demonstration on ONE host with TWO nodes. It is not a
# scale test, not a benchmark, and not evidence for any capacity claim. The
# v1.0.0 enterprise-federation certification scope is 500-1000 agents and at
# most 50 peers; nothing here extends it.
# =============================================================================
# START STATE (#5740). A variable that makes bash run code in this shell before line 1 (BASH_ENV) or changes how it
# parses (POSIXLY_CORRECT) is refused, as is any function already defined. Posix mode makes the refusal itself safe from
# functions: the special builtins export and : are found before any function, and the ${..:?} expansion exits without a
# command lookup. lab_shell_state_proven (lib/posture.sh) then proves the traps, aliases, options and attributes.
_lab_pre="${BASH_ENV+BASH_ENV }${POSIXLY_CORRECT+POSIXLY_CORRECT }"
POSIXLY_CORRECT=1
_lab_pre="$_lab_pre$(builtin declare -F)"
_lab_r=
[[ -z $_lab_pre ]] || : "${_lab_r:?run.sh refuses to start (#5740): the start environment sets or defines [$_lab_pre]; unset each one (bash -p run.sh ignores an exported function)}"
unset POSIXLY_CORRECT _lab_pre _lab_r
set -uo pipefail

LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$LAB/../.." && pwd)"
RUN="$LAB/run"

# shellcheck source=lib/common.sh
source "$LAB/lib/common.sh"
# shellcheck source=lib/posture.sh
source "$LAB/lib/posture.sh"
# #5740: refuse a shell whose traps, aliases, options or attributes are not the ones a plain bash run.sh gives.
# bash lists a DEBUG, RETURN or ERR trap only to a top-level trap -p, so the list is read here and passed in. The verdict
# is set only by the last command of a chain on its own line, so an abort or errexit anywhere in it reads as refused.
_lab_ok=0
_lab_traps=$(builtin trap -p) && lab_shell_state_proven "$_lab_traps" && _lab_ok=1
case $_lab_ok in 1) ;; *) printf 'run.sh refuses to start (#5740): %s\n' "${LAB_SHELL_WHY:-the shell-state check did not complete}" >&2; exit 78 ;; esac

# ── options ────────────────────────────────────────────────────────────────
BIN="${BIN:-}"
SIGNER="${SIGNER:-}"
CORPUS_NS_OVERRIDE=""
CORPUS_DB=""                 # optional: a FULL local corpus DB instead of the sample
CORPUS_ROWS="${CORPUS_ROWS:-2000}"   # rows to take from --corpus-db
RECALL_QUERY=""                      # P5 query; defaults per corpus (see below)
# The committed fixture is SYNTHETIC (tools/make-synthetic-corpus.sh). A real
# corpus is never committed to this public repo — see README "The corpus".
SAMPLE="$LAB/sample/lab-corpus.json"
PORT_A="${PORT_A:-19481}"
PORT_B="${PORT_B:-19482}"
KEEP=0
CAVEAT_PROBE=1
PROBE_MUTATION=0
POSTURE_SELFTEST=0

usage() {
  cat <<'USAGE'
usage: run.sh [options]

  --bin PATH          ai-memory binary (default: repo target/release, then $PATH)
  --signer PATH       attest_sign example binary (default: repo target/release/examples)
  --corpus-db PATH    load this FULL local corpus SQLite DB instead of the committed
                      text-only sample. Recall quality depends on the embedder that
                      produced the corpus matching the one the lab node runs (F-L8a);
                      the lab's default nodes run tier=keyword, i.e. lexical.
  --corpus-ns NS      namespace to slice from --corpus-db (default lab-corpus)
  --corpus-rows N     rows to take from --corpus-db (default 2000)
  --recall-query Q    query for the corpus-recall proof. Defaults to a phrase that
                      matches the committed synthetic fixture; with --corpus-db and
                      no explicit query the lab derives one from your corpus.
  --port-a N          node A port (default 19481)
  --port-b N          node B port (default 19482)
  --keep              keep run/ (daemons are still stopped) for post-mortem
  --no-caveat-probe   skip the asi-hard full-profile cold-boot probe (#2942, #4938)
  --probe-mutation    lower AI_MEMORY_REQUIRE_ROLLBACK_CHECK below its floor inside the probe and
                      require the probe to refuse for that knob (proves the probe can fail)
  --posture-selftest  run only the posture drift-guard legs (names AND values; no daemons) and exit
  -h, --help          this text
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --bin)             BIN="$2"; shift 2 ;;
    --signer)          SIGNER="$2"; shift 2 ;;
    --corpus-db)       CORPUS_DB="$2"; shift 2 ;;
    --corpus-ns)       CORPUS_NS_OVERRIDE="$2"; shift 2 ;;
    --corpus-rows)     CORPUS_ROWS="$2"; shift 2 ;;
    --recall-query)    RECALL_QUERY="$2"; shift 2 ;;
    --port-a)          PORT_A="$2"; shift 2 ;;
    --port-b)          PORT_B="$2"; shift 2 ;;
    --keep)            KEEP=1; shift ;;
    --no-caveat-probe) CAVEAT_PROBE=0; shift ;;
    --probe-mutation)  PROBE_MUTATION=1; shift ;;
    --posture-selftest) POSTURE_SELFTEST=1; shift ;;
    -h|--help)         usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

# --probe-mutation mutates the cold-boot probe; with the probe skipped it would silently run nothing.
if [ "$PROBE_MUTATION" -eq 1 ] && [ "$CAVEAT_PROBE" -eq 0 ]; then
  echo "--probe-mutation needs the cold-boot probe: it cannot be combined with --no-caveat-probe" >&2; exit 2
fi

# ── identities used throughout ─────────────────────────────────────────────
AGENT_A="ai:lab-node-a"        # node A's federation identity
AGENT_B="ai:lab-node-b"        # node B's federation identity
AUTHOR="ai:lab-author"         # the agent that authors the attested write
FED_NS="fed-lab"               # namespace for the federated write proof
CORPUS_NS="${CORPUS_NS_OVERRIDE:-lab-corpus}"   # namespace of the seeded corpus

# $CORPUS_NS reaches argv via --corpus-ns and is interpolated into the sqlite3
# probes below, so it is validated rather than trusted. Same charset as
# tools/make-local-slice.sh: alphanumerics plus the separators hierarchical
# namespaces legitimately use, and no quote, backslash, semicolon or space.
case "$CORPUS_NS" in
  *[!A-Za-z0-9_/:.@-]* | "")
    printf 'refusing unsafe --corpus-ns: %s\n' "$CORPUS_NS" >&2; exit 2 ;;
esac

if [ "$POSTURE_SELFTEST" -eq 1 ]; then
  echo "posture drift-guard legs (#5078):"
  lab_posture_selftest "$ROOT"; exit $?
fi

# Set the moment step 1 takes ownership of run/. Until then cleanup must not
# delete it: a preflight abort (a busy port, a missing binary) would otherwise
# wipe the run/ a PREVIOUS `--keep` invocation was preserving for a post-mortem
# — destroying the very evidence the operator asked to keep. Never destroy what
# this invocation did not create.
RUN_OWNED=0
cleanup() {
  lab_stop_all
  if [ "$RUN_OWNED" -eq 1 ] && [ "$KEEP" -eq 0 ]; then
    rm -rf "$RUN"
  elif [ "$RUN_OWNED" -eq 1 ]; then
    printf '\n   run dir kept at %s\n' "$RUN"
  fi
}
trap cleanup EXIT INT TERM

# ===========================================================================
step "0 · preflight"
# ===========================================================================
require_tools openssl curl jq sqlite3 || exit 1

[ -n "$BIN" ] || { [ -x "$ROOT/target/release/ai-memory" ] && BIN="$ROOT/target/release/ai-memory"; }
[ -n "$BIN" ] || BIN="$(command -v ai-memory 2>/dev/null || true)"
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
  warn "no ai-memory binary found."
  warn "  build one:  cargo build --release --bin ai-memory --example attest_sign"
  warn "  or pass:    ./run.sh --bin /path/to/ai-memory"
  exit 1
fi
[ -n "$SIGNER" ] || SIGNER="$ROOT/target/release/examples/attest_sign"
if [ ! -x "$SIGNER" ]; then
  warn "no attest_sign example at $SIGNER"
  warn "  build it:  cargo build --release --example attest_sign"
  warn "  (the lab signs its attested write with the SAME crate code the daemon"
  warn "   verifies with, so the canonical CBOR bytes are never re-implemented in bash)"
  exit 1
fi

BIN_VERSION="$(AI_MEMORY_NO_CONFIG=1 "$BIN" --version 2>/dev/null | tail -1)"
info "binary   $BIN  ($BIN_VERSION)"
info "signer   $SIGNER"
info "lab dir  $LAB"

for p in "$PORT_A" "$PORT_B"; do
  if ! lab_port_free "$p"; then
    warn "port $p is already in use — pass --port-a/--port-b to move the lab"
    exit 1
  fi
done

# Posture drift guard: the lab's knob list AND values must still be the SSOT's
# (src/security_profile.rs::KNOBS). A kit whose posture silently drifted from the code
# would be demonstrating a posture that no longer exists.
drift="$(lab_posture_ssot_check "$ROOT")"; drift_rc=$?
case "$drift_rc" in
  0) ok  "asi-hard posture list matches src/security_profile.rs::KNOBS — $drift" ;;
  1) no  "asi-hard posture DRIFT: $drift" ;;
  *) info "posture SSOT check: $drift" ;;
esac

# ===========================================================================
step "1 · workspace"
# ===========================================================================
rm -rf "$RUN"
RUN_OWNED=1
mkdir -p "$RUN"/{crypto,evidence,author-keys,governance}
mkdir -p "$RUN"/node-a/{home/.config/ai-memory,keys} "$RUN"/node-b/{home/.config/ai-memory,keys}
info "work dir $RUN (removed and recreated — this run is idempotent)"
info "nothing is written outside this directory: no /tmp, no \$HOME"

ADB="$RUN/node-a/node.db"; BDB="$RUN/node-b/node.db"
ALOG="$RUN/node-a/daemon.log"; BLOG="$RUN/node-b/daemon.log"
KA="$RUN/node-a/keys"; KB="$RUN/node-b/keys"; KAUTH="$RUN/author-keys"
# #3198: identity generate refuses a group- or world-writable key dir, so pin 0700 explicitly (the umask is the caller's).
chmod 0700 "$KA" "$KB" "$KAUTH" "$RUN/governance"

# tier = keyword. The lab proves federation, mTLS and attestation — none of
# which need an embedder — so the nodes must not try to download or load one.
# NOTE (#2852): the config resolver reads $HOME/.config/ai-memory/config.toml
# and IGNORES XDG_CONFIG_HOME, so the file goes under each node's private
# HOME. We assert below that the daemon actually LOADED it rather than
# assuming an override took effect.
for n in a b; do
  printf 'schema_version = 2\ntier = "keyword"\n' > "$RUN/node-$n/home/.config/ai-memory/config.toml"
done

# ===========================================================================
step "2 · crypto material (calls infra/do-hive/crypto/gen-certs.sh)"
# ===========================================================================
GENCERTS="$ROOT/infra/do-hive/crypto/gen-certs.sh"
# `-f`, not `-x`: the generator is invoked as `bash "$GENCERTS"`, so the execute
# bit is irrelevant, and requiring it would fail the release-tarball path that
# lib/posture.sh already contemplates (an archive extraction commonly drops
# modes). git stores it 100755; this just does not depend on that surviving.
if [ ! -f "$GENCERTS" ]; then
  no "prior-art cert generator not found at $GENCERTS"
  summary; exit 1
fi
OUT="$RUN/crypto"
if OUT_DIR="$OUT" bash "$GENCERTS" > "$RUN/evidence/gen-certs.out" 2>&1; then
  ok "gen-certs.sh minted the CA + peer/client leaves into run/crypto"
else
  no "gen-certs.sh failed — see run/evidence/gen-certs.out"
  summary; exit 1
fi
info "peerA fp $(awk '/^peerA/{print $2}' "$OUT/fingerprints.txt")"
info "peerB fp $(awk '/^peerB/{print $2}' "$OUT/fingerprints.txt")"
info "each node's allowlist pins ONLY the other node's client cert (SSH known_hosts model:"
info "the FINGERPRINT is the trust anchor, not the CA — client-bad is signed by the same CA"
info "and is still refused, which is exactly what step 6 asserts)"

# ===========================================================================
step "3 · identities, cross-peer enrollment, agent key binding"
# ===========================================================================
# Each node gets a federation identity; each enrolls the OTHER's public half,
# so the transport lane (FED_REQUIRE_SIG / _NONCE / _PEER_ENROLLMENT, all
# default-on in v1.0.0) is satisfied by REAL enrollment, not an escape hatch.
AI_MEMORY_NO_CONFIG=1 "$BIN" identity generate --agent-id "$AGENT_A" --key-dir "$KA" >/dev/null 2>&1
AI_MEMORY_NO_CONFIG=1 "$BIN" identity generate --agent-id "$AGENT_B" --key-dir "$KB" >/dev/null 2>&1
cp "$KA/$AGENT_A.pub" "$KB/$AGENT_A.pub"
cp "$KB/$AGENT_B.pub" "$KA/$AGENT_B.pub"
if [ -s "$KB/$AGENT_A.pub" ] && [ -s "$KA/$AGENT_B.pub" ]; then
  ok "cross-peer federation identities enrolled ($AGENT_A ↔ $AGENT_B)"
else
  no "cross-peer federation identity enrollment failed"
fi

# The author key: generated once, registered + BOUND on BOTH node databases so
# the receiving node can verify the author's signature on the relayed write.
AI_MEMORY_NO_CONFIG=1 "$BIN" identity generate --agent-id "$AUTHOR" --key-dir "$KAUTH" >/dev/null 2>&1
AUTHOR_PUB="$(AI_MEMORY_NO_CONFIG=1 "$BIN" identity export-pub --agent-id "$AUTHOR" --key-dir "$KAUTH" 2>/dev/null | tail -1)"
if [ -z "$AUTHOR_PUB" ]; then
  no "could not export the author public key"
  summary; exit 1
fi

# --- #2941 guard ----------------------------------------------------------
# `agents bind-key` has been observed to silently no-op (~1 run in 4 on a
# fresh DB): the registry row is created but `metadata.agent_pubkey` is never
# set, and every subsequent signed write then 403s with ATTESTATION_FAILED —
# a failure that looks like a bug in attestation rather than in enrollment,
# because `agents list` does not expose the pubkey. So: bind, then READ THE
# BOUND KEY BACK from the `_agents` registry row, and fail LOUD naming the
# issue if it is not there.
bound_pubkey() {  # <db>
  sqlite3 -cmd '.timeout 3000' "$1" \
    "SELECT COALESCE(json_extract(metadata,'\$.agent_pubkey'),'') FROM memories
     WHERE namespace='_agents' AND title='agent:$AUTHOR' LIMIT 1;" 2>/dev/null
}

for DB in "$ADB" "$BDB"; do
  label="$(basename "$(dirname "$DB")")"
  attempt=0; bound=""
  while [ "$attempt" -lt 3 ]; do
    attempt=$((attempt + 1))
    AI_MEMORY_NO_CONFIG=1 "$BIN" agents register --agent-id "$AUTHOR" --agent-type system --db "$DB" >/dev/null 2>&1
    # #3464: bind-key proves possession in-process from the local key store, so point it at the author key dir.
    AI_MEMORY_KEY_DIR="$KAUTH" AI_MEMORY_NO_CONFIG=1 "$BIN" agents bind-key --agent-id "$AUTHOR" --pubkey "$AUTHOR_PUB" --db "$DB" >/dev/null 2>&1
    bound="$(bound_pubkey "$DB")"
    [ "$bound" = "$AUTHOR_PUB" ] && break
    warn "bind-key attempt $attempt on $label did not persist metadata.agent_pubkey (issue #2941) — retrying"
    sleep 0.5
  done
  if [ "$bound" = "$AUTHOR_PUB" ]; then
    ok "$label: author pubkey bound AND read back from the _agents registry row (#2941 guard, attempt $attempt)"
  else
    no "$label: agents bind-key silently no-opped — metadata.agent_pubkey is unset after $attempt attempts."
    warn "  This is the known intermittent enrollment flake, issue #2941."
    warn "  Every signed write will now 403 ATTESTATION_FAILED. Re-run the lab; if it"
    warn "  reproduces, attach run/node-*/daemon.log and the attempt count to #2941."
  fi
done

# ===========================================================================
step "4 · seed the corpus (bootstrap phase — deliberately NOT hardened)"
# ===========================================================================
# Under the hardened posture EVERY direct write must be attested, so a corpus
# cannot be bulk-loaded through the hardened surface — and should not be: this
# is the offline provisioning phase, the same one a real deployment performs
# before the node ever listens. It is called out here rather than hidden
# because "the corpus was seeded under a weaker posture than it is served
# under" is exactly the kind of thing a reader deserves to be told.
SEED_SRC_DESC=""
if [ -n "$CORPUS_DB" ]; then
  if [ ! -f "$CORPUS_DB" ]; then
    no "--corpus-db $CORPUS_DB does not exist"
    summary; exit 1
  fi
  # Reuse the SAME normalisation the committed sample was built with —
  # tools/make-local-slice.sh — rather than a second, subtly-different export
  # path here. The expiry normalisation it performs is not cosmetic: without
  # it a corpus whose rows carry a stale TTL exports almost nothing AND
  # imports already-expired (see the header of that script).
  SEED_FILE="$RUN/node-a/corpus.json"
  if ! "$LAB/tools/make-local-slice.sh" --bin "$BIN" --corpus-db "$CORPUS_DB" \
        --namespace "$CORPUS_NS" --rows "$CORPUS_ROWS" --out "$SEED_FILE" \
        > "$RUN/evidence/corpus-build.out" 2>&1; then
    no "could not build a corpus slice from $CORPUS_DB — see run/evidence/corpus-build.out"
    summary; exit 1
  fi
  SEED_SRC_DESC="full local corpus $CORPUS_DB (up to $CORPUS_ROWS rows of '$CORPUS_NS')"
  warn "F-L8a: recall quality over a full corpus depends on the lab node's embedder"
  warn "  matching the one that produced its vectors. These nodes run tier=keyword"
  warn "  (lexical), so semantic ranking is NOT what is being demonstrated."
else
  SEED_FILE="$SAMPLE"
  SEED_SRC_DESC="committed SYNTHETIC fixture $(basename "$SAMPLE")"
fi

if [ ! -s "$SEED_FILE" ]; then
  no "corpus file $SEED_FILE is missing or empty"
  summary; exit 1
fi
SEED_ROWS="$(jq -r '.count // (.memories|length) // 0' "$SEED_FILE" 2>/dev/null || echo 0)"
# No --trust-source: the lab operator is the author of its own seeded corpus,
# so the rows are restamped with $AUTHOR (the original claim is preserved in
# metadata.imported_from_agent_id, so no provenance is lost). This keeps
# ownership coherent with the agent the lab later recalls as.
AI_MEMORY_NO_CONFIG=1 AI_MEMORY_AGENT_ID="$AUTHOR" \
  "$BIN" import --db "$ADB" < "$SEED_FILE" \
  > "$RUN/evidence/import.out" 2>&1
LOADED="$(sqlite3 -cmd '.timeout 5000' "$ADB" \
  "SELECT COUNT(*) FROM memories WHERE namespace='$CORPUS_NS';" 2>/dev/null || echo 0)"
# PRESENT is not the same as RECALLABLE. A row whose expires_at is already in
# the past sits in `memories` — a COUNT(*) reports it happily — while recall's
# `expires_at IS NULL OR expires_at > now` filter skips it and the next gc tick
# archives it away mid-run. That is precisely the failure this guard exists to
# catch, because "300 rows loaded, 0 rows recallable" otherwise reads as a
# broken recall rather than an expired fixture.
LIVE="$(sqlite3 -cmd '.timeout 5000' "$ADB" \
  "SELECT COUNT(*) FROM memories WHERE namespace='$CORPUS_NS'
     AND (expires_at IS NULL OR expires_at > datetime('now'));" 2>/dev/null || echo 0)"
if [ "${LOADED:-0}" -gt 0 ] && [ "${LIVE:-0}" -eq "${LOADED:-0}" ]; then
  ok "node-a seeded with $LOADED rows in namespace '$CORPUS_NS', all unexpired (from the $SEED_SRC_DESC; file declares $SEED_ROWS)"
elif [ "${LOADED:-0}" -gt 0 ]; then
  no "node-a seeded $LOADED rows in '$CORPUS_NS' but only $LIVE are unexpired — recall will not see the rest, and gc will archive them"
  warn "  A corpus fixture must carry no live TTL. Rebuild the slice with tools/make-local-slice.sh,"
  warn "  which stamps the slice long-tier (permanent) precisely to avoid this."
else
  no "corpus seeding produced 0 rows in '$CORPUS_NS' — see run/evidence/import.out"
fi

# ===========================================================================
step "5 · asi-hard posture"
# ===========================================================================
lab_posture_render | tee "$RUN/evidence/posture.env" | sed 's/^/   /'
info "$(lab_posture_count) pinned knobs at their hard floor."
info "AI_MEMORY_SECURITY_PROFILE is deliberately NOT set (every knob is pinned directly) — see README §asi-hard."

# #5739: the probe block must record exactly one verdict. A failed assignment (a readonly or integer variable, an
# arithmetic error) aborts a whole top-level compound in bash, which would skip the block's ok or no silently.
LAB_PROBE_AT=$((LAB_PASS + LAB_FAIL))
if [ "$CAVEAT_PROBE" -eq 1 ]; then
  # PROVE the full profile cold-boots (#2942 fixed, #4938): boot a throwaway node
  # under the FULL asi-hard profile and record what actually happens.
  PROBE="$RUN/evidence/caveat-asi-hard-coldboot.txt"
  PROBE_HOME="$RUN/probe-home"; mkdir -p "$PROBE_HOME/.config/ai-memory"
  printf 'schema_version = 2\ntier = "keyword"\n' > "$PROBE_HOME/.config/ai-memory/config.toml"
  PROBE_PORT="$((PORT_B + 1))"
  {
    echo "# asi-hard full-profile cold-boot probe on a FRESH database (issue #2942)"
    echo "# command: AI_MEMORY_SECURITY_PROFILE=asi-hard ai-memory serve --db <fresh> ..."
    echo
  } > "$PROBE"
  if ! lab_port_free "$PROBE_PORT"; then
    no "cold-boot probe cannot run: port $PROBE_PORT is occupied, so a non-zero exit would prove nothing"
  else
    # --probe-mutation lowers the rollback-check knob below its floor so the profile refuses the boot:
    # the boot must then refuse naming that knob (the pin-and-refuse path), which proves the probe can fail.
    PROBE_MUT=""
    if [ "$PROBE_MUTATION" -eq 1 ]; then PROBE_MUT="0"; fi
    # #3582: the profile refuses a federation config with no peer allowlist, so give the probe one;
    # otherwise it would refuse for THAT reason and not for a knob under test.
    ( export HOME="$PROBE_HOME" AI_MEMORY_SECURITY_PROFILE=asi-hard AI_MEMORY_KEY_DIR="$RUN/governance"
      export AI_MEMORY_FED_PEER_ATTESTATION="{\"$AGENT_A\":{\"allowed_namespaces\":[\"$FED_NS\"]}}"
      if [ -n "$PROBE_MUT" ]; then export AI_MEMORY_REQUIRE_ROLLBACK_CHECK="$PROBE_MUT"; fi
      timeout 60 "$BIN" serve --host 127.0.0.1 --port "$PROBE_PORT" --db "$RUN/probe.db" \
        --tls-cert "$OUT/server.crt" --tls-key "$OUT/server.key" \
        --mtls-allowlist "$OUT/allowlist.txt" ) >>"$PROBE" 2>&1
    PROBE_RC=$?
    echo "exit_code=$PROBE_RC" >> "$PROBE"
    # #4938: the proof is a node that actually came up. Neither a non-zero exit alone nor the word
    # "rollback" proves anything: the profile prints an INFO pin line naming the knob on every boot,
    # and a node that booted and was killed by `timeout` exits 124. A boot that REFUSES (#2942, or any
    # other refusal) is a FAIL: the lab runs the full posture, so the full profile must cold-boot.
    if grep -q "listening on" "$PROBE" && { [ "$PROBE_RC" -eq 124 ] || [ "$PROBE_RC" -eq 0 ]; }; then
      if [ "$PROBE_MUTATION" -eq 1 ]; then
        no "probe MUTATION NOT DETECTED: the node listened with AI_MEMORY_REQUIRE_ROLLBACK_CHECK=0 under the profile (exit $PROBE_RC)"
      else
        ok "full asi-hard cold boot on a fresh DB succeeded (listening, exit $PROBE_RC after the probe timeout) — evidence in run/evidence/caveat-asi-hard-coldboot.txt"
      fi
    else
      if [ "$PROBE_MUTATION" -eq 1 ]; then
        # The mutation is detected only when the refusal names the lowered knob. Any other refusal
        # (port, config, a different knob) proves nothing about this probe, and the profile's INFO
        # pin line names the knob on every boot, so it is excluded.
        # #5662, #5664: lab_probe_verdict reports by assignment (no output command on the verdict path), and
        # lab_probe_report turns the verdict into the line and the outcome: only detected is ok; not-detected and
        # every refused verdict (the guard refused, or the child exited with a status that is not a verdict) are no.
        lab_probe_verdict "$PROBE"
        if lab_probe_report "$LAB_PROBE_VERDICT" "$PROBE_RC"; then ok "$LAB_PROBE_LINE"; else no "$LAB_PROBE_LINE"; fi
      else
        no "full asi-hard cold boot on a fresh DB did NOT come up (exit $PROBE_RC): the lab runs this posture, so a refusal is a failure (#2942 regression or a new refusal)"
      fi
      info "$(grep -iE 'rollback|refuse|fatal' "$PROBE" | tail -2 | sed 's/^/     /')"
    fi
    rm -f "$RUN/probe.db"*
  fi
fi
# #5739: exactly one verdict, counted on variables that carry no attribute. This is its own top-level statement, and the
# next one reads its status, so an abort of the check itself (status 1) fails the run too.
[[ $CAVEAT_PROBE != 1 || ( -z ${LAB_PROBE_AT@a}${LAB_PASS@a}${LAB_FAIL@a} && $((LAB_PASS + LAB_FAIL - LAB_PROBE_AT)) == 1 ) ]]
case $? in 0) ;; *) printf '   FAIL the cold-boot probe did not record exactly one verdict (PASS %s, FAIL %s, %s before it): a verdict that could not be written fails the run (#5739)\n' "${LAB_PASS-?}" "${LAB_FAIL-?}" "${LAB_PROBE_AT-?}"; exit 1 ;; esac
# end of the cold-boot probe verdict count (#5739)

# ===========================================================================
step "6 · launch the two-node mTLS federation"
# ===========================================================================
# Topology (mutual mTLS, quorum W-of-N = 2), following test-federation-mtls.sh:
#   node-a :$PORT_A  server=peerA.crt  allowlist pins peerB's client cert
#   node-b :$PORT_B  server=peerB.crt  allowlist pins peerA's client cert
# Each fans its writes to the other using its OWN cert as the outbound client
# cert and verifies the peer's server cert against the shared CA.
launch_node() { # <name> <port> <db> <keydir> <fedid> <homedir> <peerport> <servercert> <serverkey> <allowlist> <log> <peerfedid>
  local name="$1" port="$2" db="$3" keydir="$4" fedid="$5" home="$6" peer="$7" sc="$8" sk="$9" al="${10}" log="${11}" peerfed="${12}"
  (
    lab_posture_export
    export HOME="$home"
    export AI_MEMORY_KEY_DIR="$keydir"
    export AI_MEMORY_FED_IDENTITY="$fedid"
    # #3582: FED_REQUIRE_PUSH_NAMESPACE_SCOPE is pinned, so key enrollment alone grants no namespace
    # scope: name the namespaces the peer may write.
    export AI_MEMORY_FED_PEER_ATTESTATION="{\"$peerfed\":{\"allowed_namespaces\":[\"$FED_NS\",\"$CORPUS_NS\"]}}"
    export AI_MEMORY_WITNESS_KEY_DIR="$RUN/governance"
    export RUST_LOG="${RUST_LOG:-ai_memory=info,federation=debug}"
    exec "$BIN" serve --host 127.0.0.1 --port "$port" --db "$db" \
      --tls-cert "$sc" --tls-key "$sk" --mtls-allowlist "$al" \
      --quorum-writes 2 --quorum-peers "https://127.0.0.1:$peer" \
      --quorum-client-cert "$sc" --quorum-client-key "$sk" \
      --quorum-ca-cert "$OUT/ca.crt" --quorum-timeout-ms 8000
  ) >"$log" 2>&1 &
  lab_track_pid $!
  info "$name pid $! on https://127.0.0.1:$port"
}

launch_node node-a "$PORT_A" "$ADB" "$KA" "$AGENT_A" "$RUN/node-a/home" "$PORT_B" \
  "$OUT/peerA.crt" "$OUT/peerA.key" "$OUT/peerA.allowlist" "$ALOG" "$AGENT_B"
launch_node node-b "$PORT_B" "$BDB" "$KB" "$AGENT_B" "$RUN/node-b/home" "$PORT_A" \
  "$OUT/peerB.crt" "$OUT/peerB.key" "$OUT/peerB.allowlist" "$BLOG" "$AGENT_A"

# peerB's cert is the client peerA trusts, and vice versa.
CA_CLIENT=("$OUT/peerB.crt" "$OUT/peerB.key")
CB_CLIENT=("$OUT/peerA.crt" "$OUT/peerA.key")

if lab_wait_https "https://127.0.0.1:$PORT_A/api/v1/health" "${CA_CLIENT[@]}" 120 \
   && lab_wait_https "https://127.0.0.1:$PORT_B/api/v1/health" "${CB_CLIENT[@]}" 120; then
  ok "both nodes answer /api/v1/health over mutual TLS with a PINNED client cert"
else
  no "one or both nodes never became reachable — see run/node-*/daemon.log"
  info "$(tail -5 "$ALOG" | sed 's/^/     A| /')"
  info "$(tail -5 "$BLOG" | sed 's/^/     B| /')"
  summary; exit 1
fi

# The tier override must have been LOADED, not merely written (#2852): an
# unread config silently boots the compiled default tier, which on a laptop
# with no model cache means an embedder download attempt and a boot race.
if grep -q "loaded config from $RUN/node-a/home/.config/ai-memory/config.toml" "$ALOG"; then
  ok "node-a loaded its private config (tier=keyword) — no embedder, no network"
else
  no "node-a did not load its private config; the tier override was inert (#2852 shape)"
fi

# ===========================================================================
step "7 · negative lanes — what MUST be refused"
# ===========================================================================
# N1 — a well-formed cert signed by the SAME CA but NOT on the allowlist.
if curl -sk --max-time 8 --cert "$OUT/client-bad.crt" --key "$OUT/client-bad.key" \
     "https://127.0.0.1:$PORT_B/api/v1/health" -o /dev/null 2>/dev/null; then
  no "N1 unpinned client cert reached node-b (the fingerprint allowlist is NOT enforcing)"
else
  ok "N1 unpinned client cert refused at node-b's TLS layer (same CA, absent from the allowlist)"
fi

# N2 — plaintext HTTP against the mTLS port.
if curl -s --max-time 8 "http://127.0.0.1:$PORT_B/api/v1/health" -o /dev/null 2>/dev/null; then
  no "N2 plaintext http reached node-b"
else
  ok "N2 plaintext http refused at node-b's mTLS port"
fi

# N3 — an unsigned write under required attestation.
UNSIGNED_BODY="$(jq -nc --arg t "unsigned-probe-$$" --arg ns "$FED_NS" \
  '{title:$t,content:"an unsigned direct write that the hardened posture must refuse",namespace:$ns,tier:"mid"}')"
n3="$(curl -sk --cert "${CA_CLIENT[0]}" --key "${CA_CLIENT[1]}" --max-time 20 \
  -H "x-agent-id: $AUTHOR" -H 'content-type: application/json' \
  -X POST "https://127.0.0.1:$PORT_A/api/v1/memories" -d "$UNSIGNED_BODY" -w $'\n%{http_code}' 2>/dev/null)"
n3code="$(printf '%s' "$n3" | tail -1)"; n3json="$(printf '%s' "$n3" | sed '$d')"
n3err="$(printf '%s' "$n3json" | jq -r '.code // empty' 2>/dev/null)"
if [ "$n3code" = "403" ]; then
  ok "N3 unsigned write refused 403${n3err:+ $n3err} under AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1"
else
  no "N3 unsigned write got '$n3code' (expected 403) — $n3json"
fi

# N4 — the no-disable contract itself: asi-hard must REFUSE to boot when a
# pinned knob is set BELOW its hard floor. This is the property that makes
# the posture a posture rather than a suggestion.
N4LOG="$RUN/evidence/no-disable-refusal.txt"
N4HOME="$RUN/n4-home"; mkdir -p "$N4HOME/.config/ai-memory"
N4PORT="$((PORT_B + 2))"
printf 'schema_version = 2\ntier = "keyword"\n' > "$N4HOME/.config/ai-memory/config.toml"
if ! lab_port_free "$N4PORT"; then
  no "N4 cannot run: port $N4PORT is occupied, so a refusal would be unattributable"
else
  ( HOME="$N4HOME" AI_MEMORY_SECURITY_PROFILE=asi-hard AI_MEMORY_SECRET_SCREEN_MODE=off \
    timeout 40 "$BIN" serve --host 127.0.0.1 --port "$N4PORT" --db "$RUN/n4.db" \
      --tls-cert "$OUT/server.crt" --tls-key "$OUT/server.key" \
      --mtls-allowlist "$OUT/allowlist.txt" ) >"$N4LOG" 2>&1
  n4rc=$?
  # The refusal must NAME the loosened knob. Accepting any non-zero exit would
  # let an unrelated startup failure — a bad cert path, a bind collision — pass
  # as proof that the posture enforced itself, which is the exact false-green
  # this lane exists to rule out.
  if [ "$n4rc" -ne 0 ] && grep -qi "SECRET_SCREEN_MODE" "$N4LOG"; then
    ok "N4 asi-hard REFUSED to boot with a loosened pin (exit $n4rc, names AI_MEMORY_SECRET_SCREEN_MODE) — the no-disable contract holds"
  elif [ "$n4rc" -ne 0 ]; then
    no "N4 boot failed (exit $n4rc) but the message does not name the loosened knob — unattributable, see run/evidence/no-disable-refusal.txt"
    info "$(tail -3 "$N4LOG" | sed 's/^/     /')"
  else
    no "N4 asi-hard BOOTED with AI_MEMORY_SECRET_SCREEN_MODE=off — the no-disable contract did not hold"
  fi
  rm -f "$RUN/n4.db"*
fi

# ===========================================================================
step "8 · positive lanes — attested write, replication, federated recall"
# ===========================================================================
TITLE="fed-lab-attested-$$"
CONTENT="A v1.0.0 laptop federation lab probe: an agent-attested memory authored on node-a that must replicate across the mutually authenticated quorum mesh and be recallable at node-b."
CREATED="$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"

SIG="$("$SIGNER" --agent-id "$AUTHOR" --namespace "$FED_NS" --title "$TITLE" \
        --kind observation --created-at "$CREATED" --content "$CONTENT" \
        --priv-file "$KAUTH/$AUTHOR.priv" 2>"$RUN/evidence/sign.err")"
if [ -z "$SIG" ]; then
  no "P1 attest_sign produced no signature — $(head -2 "$RUN/evidence/sign.err")"
else
  BODY="$(jq -nc --arg t "$TITLE" --arg c "$CONTENT" --arg ns "$FED_NS" --arg sig "$SIG" --arg ca "$CREATED" \
    '{title:$t,content:$c,namespace:$ns,tier:"mid",signature:$sig,created_at:$ca}')"
  presp="$(curl -sk --cert "${CA_CLIENT[0]}" --key "${CA_CLIENT[1]}" --max-time 30 \
    -H "x-agent-id: $AUTHOR" -H 'content-type: application/json' \
    -X POST "https://127.0.0.1:$PORT_A/api/v1/memories" -d "$BODY" -w $'\n%{http_code}' 2>/dev/null)"
  pcode="$(printf '%s' "$presp" | tail -1)"; pjson="$(printf '%s' "$presp" | sed '$d')"
  PID_="$(printf '%s' "$pjson" | jq -r '.id // empty' 2>/dev/null)"
  if { [ "$pcode" = "201" ] || [ "$pcode" = "202" ]; } && [ -n "$PID_" ]; then
    ok "P1 attested write accepted at node-a (HTTP $pcode, id=$PID_)"
  else
    no "P1 attested write got '$pcode' — $pjson"
  fi

  # P2 — the row is ATTESTED at node-a, not merely accepted.
  alvl="$(sqlite3 -cmd '.timeout 3000' "$ADB" \
    "SELECT COALESCE(json_extract(metadata,'\$.attest_level'),'') FROM memories
     WHERE namespace='$FED_NS' AND title='$TITLE' LIMIT 1;" 2>/dev/null)"
  if [ "$alvl" = "agent_attested" ]; then
    ok "P2 node-a stored it at attest_level=agent_attested (signature verified against the bound key)"
  else
    no "P2 node-a attest_level='${alvl:-<row absent>}' (expected agent_attested)"
  fi

  # P3 — REPLICATION. Read node-b's own database: that is the receiver's
  # ground truth, and it sidesteps the #1468 private-scope read filter that
  # can hide another agent's rows from an HTTP reader.
  blvl=""
  for _ in $(seq 1 60); do
    blvl="$(sqlite3 -cmd '.timeout 3000' "$BDB" \
      "SELECT COALESCE(json_extract(metadata,'\$.attest_level'),'present-no-level') FROM memories
       WHERE namespace='$FED_NS' AND title='$TITLE' LIMIT 1;" 2>/dev/null)"
    [ -n "$blvl" ] && break
    sleep 0.5
  done
  if [ "$blvl" = "agent_attested" ]; then
    ok "P3 the write REPLICATED to node-b over the mTLS quorum channel and arrived agent_attested"
  elif [ -n "$blvl" ]; then
    no "P3 the write reached node-b but at attest_level='$blvl' (expected agent_attested)"
  else
    no "P3 the write never reached node-b — $(grep -iE 'quorum|push|write.?sig|enroll' "$BLOG" | tail -2 | tr '\n' ' ')"
  fi

  # P4 — FEDERATED RECALL: ask node-b, which never saw the original request.
  rq="$(curl -sk --cert "${CB_CLIENT[0]}" --key "${CB_CLIENT[1]}" --max-time 30 -G \
    -H "x-agent-id: $AUTHOR" \
    --data-urlencode "q=agent-attested memory replicate quorum mesh" \
    --data-urlencode "namespace=$FED_NS" --data-urlencode "limit=10" \
    "https://127.0.0.1:$PORT_B/api/v1/recall" 2>/dev/null)"
  hit="$(printf '%s' "$rq" | jq -r --arg t "$TITLE" \
    '[(.memories // .results // .) | .[]? | select(.title == $t)] | length' 2>/dev/null || echo 0)"
  if [ "${hit:-0}" -ge 1 ]; then
    ok "P4 federated recall: node-b returns the memory that was written to node-a"
  else
    no "P4 federated recall at node-b returned no match — $(printf '%s' "$rq" | head -c 300)"
  fi
fi

# P5 — recall over the seeded corpus on node-a.
#
# The query has to suit whatever corpus was actually seeded, so it is resolved
# rather than hardcoded: an explicit --recall-query always wins; the committed
# synthetic fixture has a known vocabulary and gets a fixed phrase; and a
# --corpus-db run with no query DERIVES one from the corpus itself (words from
# a seeded title) so the proof works on data this kit has never seen. A derived
# query is a weaker proof than an authored one — it shows the FTS index, the
# query path and the visibility filter all work end-to-end, but not that the
# corpus answers a question posed independently of it — so the run says which
# kind it used rather than presenting them as equivalent.
CORPUS_QUERY_KIND="explicit"
if [ -z "$RECALL_QUERY" ]; then
  if [ -n "$CORPUS_DB" ]; then
    RECALL_QUERY="$(sqlite3 -cmd '.timeout 5000' "$ADB" \
      "SELECT title FROM memories WHERE namespace='$CORPUS_NS' ORDER BY id LIMIT 1;" 2>/dev/null \
      | tr -cs '[:alnum:]' ' ' | awk '{ for (i = 1; i <= NF && i <= 4; i++) printf "%s ", $i }')"
    CORPUS_QUERY_KIND="derived from the seeded corpus"
  else
    # Matches the synthetic fixture's vocabulary (see tools/make-synthetic-corpus.sh).
    RECALL_QUERY="ballast scheduling harbour rotation"
    CORPUS_QUERY_KIND="fixture-authored"
  fi
fi
if [ -z "${RECALL_QUERY// /}" ]; then
  no "P5 could not resolve a corpus recall query — pass --recall-query"
  RECALL_QUERY="__unresolved__"
fi
info "corpus query ($CORPUS_QUERY_KIND): $RECALL_QUERY"
cq="$(curl -sk --cert "${CA_CLIENT[0]}" --key "${CA_CLIENT[1]}" --max-time 30 -G \
  -H "x-agent-id: $AUTHOR" \
  --data-urlencode "q=$RECALL_QUERY" \
  --data-urlencode "namespace=$CORPUS_NS" --data-urlencode "limit=5" \
  "https://127.0.0.1:$PORT_A/api/v1/recall" 2>/dev/null)"
chits="$(printf '%s' "$cq" | jq -r '[(.memories // .results // .) | .[]?] | length' 2>/dev/null || echo 0)"
if [ "${chits:-0}" -ge 1 ]; then
  ok "P5 corpus recall on node-a returned $chits result(s) from '$CORPUS_NS' (lexical — tier=keyword, query $CORPUS_QUERY_KIND)"
  info "top hit: $(printf '%s' "$cq" | jq -r '((.memories // .results // .)[0].title) // "?"' 2>/dev/null)"
else
  no "P5 corpus recall on node-a returned nothing — $(printf '%s' "$cq" | head -c 300)"
fi

# ===========================================================================
step "9 · run manifest"
# ===========================================================================
{
  echo "ai-memory laptop federation lab"
  echo "generated_at:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "binary:         $BIN"
  echo "binary_version: $BIN_VERSION"
  echo "host:           $(uname -srm)"
  echo "nodes:          node-a https://127.0.0.1:$PORT_A , node-b https://127.0.0.1:$PORT_B"
  echo "corpus:         $SEED_SRC_DESC (${LOADED:-0} rows in $CORPUS_NS)"
  echo "posture:        $(lab_posture_count) asi-hard knobs at hard floor (every KNOBS row)"
  echo "result:         $LAB_PASS PASS / $LAB_FAIL FAIL"
} > "$RUN/evidence/manifest.txt"
cat "$RUN/evidence/manifest.txt" | sed 's/^/   /'

summary
rc=$?
if [ "$rc" -eq 0 ]; then
  printf '\n   %sfederation lab GREEN%s — %d assertions passed.\n' "$C_OK" "$C_0" "$LAB_PASS"
else
  printf '\n   %sfederation lab RED%s — see the FAIL rows above; logs in run/node-*/daemon.log\n' "$C_NO" "$C_0"
  [ "$KEEP" -eq 0 ] && printf '   re-run with --keep to preserve run/ for a post-mortem.\n'
fi
exit "$rc"
