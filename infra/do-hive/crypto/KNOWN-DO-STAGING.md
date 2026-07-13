# DO staging requirements for the crypto attestation legs

These legs (`test-fed-write-sig-attestation.sh` + the sibling `test-*.sh`) are
self-contained: each stands up its own local daemons and asserts pos/neg. They
run GREEN locally at HEAD. When re-hosting them onto DigitalOcean droplets for a
Gate-3 ship-gate, three ENVIRONMENT-staging steps are on the ORCHESTRATOR (the
`spawn.sh apply` → SSH → run wrapper), not the legs. A 2026-07-13 DO round hit
each of these as a harness-staging gap (never a product/attestation defect —
the same legs pass locally 7/7 and the DO NEGATIVE + mTLS + store-attestation
legs passed on real droplets). Fold these into whatever orchestrator drives the
next DO round.

## 1. Ship the leg script + its deps onto every droplet BEFORE invoking it

The failure that aborted the focused re-run was simply:

    bash: test-fed-write-sig-attestation.sh: No such file or directory

`scp`/`rsync` the whole `crypto/` dir (all `test-*.sh` + `gen-certs.sh`) plus the
release binary + the `attest_sign` example onto each droplet, `chmod +x`, and
run from that directory. Verify presence (`ssh <host> 'ls /root/crypto'`) before
invoking. Also install the leg's runtime deps on the droplet — the base
ubuntu-24.04 image lacks some: **`sqlite3`** (the pos/neg readback queries the
receiver DB directly), `jq`, `git` (the AUD probe spawns `git`), `openssl`,
`curl`.

## 2. No embedder model needed — the leg now boots `tier=keyword`

Historically the leg's daemons booted the compiled-default `tier=semantic`,
which on a FRESH droplet with no MiniLM cache logged `EMBEDDER LOAD FAILED` and
paid a semantic-tier boot delay that RACED the POSITIVE poll window (POS.B
false-negative on DO; green locally where the model is cached). **Fixed in the
leg**: the two daemons now boot at `tier=keyword` via an isolated
`XDG_CONFIG_HOME` config (`serve` has no `--tier` flag — tier resolves from
`config.toml` only), so they need NO embedder at all. Nothing to stage.

If you run a leg that genuinely needs semantic recall on a droplet, pre-stage
the model instead: `scp -r ~/.cache/huggingface/hub/models--sentence-transformers--all-MiniLM-L6-v2`
to `/root/.cache/huggingface/hub/` (+ a `snapshots/main` symlink to the hash
snapshot), or set `AI_MEMORY_EMBED_OFFLINE=1` and accept the loud keyword
degrade (#1593).

## 3. Cross-host bind needs `--api-key` (a positive security control)

If the orchestrator also runs a genuine cross-HOST mTLS leg (peerA on droplet-1,
peerB on droplet-2 over the VPC), the daemon will **correctly refuse** to bind a
non-loopback address without an api_key (v0.7.0 S5-C1 — refusing to expose every
privileged endpoint to any caller that reaches the bind). Pass `--api-key <k>`
on the `serve` bind and send `-H 'x-api-key: <k>'` from the client. This is the
product's security posture working as designed, not a bug; the orchestrator just
has to satisfy it. (The self-contained legs bind loopback only, so they are
unaffected.)

---

Teardown discipline is absolute regardless of any of the above: arm an
unconditional `trap teardown EXIT INT TERM` immediately after `spawn.sh apply`,
and confirm `doctl compute droplet list` is EMPTY at the end.
