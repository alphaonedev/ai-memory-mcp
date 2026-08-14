<!-- Copyright 2026 AlphaOne LLC / SPDX-License-Identifier: Apache-2.0 -->

# cert-54 evidence sanitization (2026-08-13 re-capture)

These files are **recorded artifacts** of the §5.4(2)/(5) localhost runs
the certification cites. The 2026-08-12 first capture was superseded on
2026-08-13 by a full re-capture at the post-remediation tree (the merged
cert-remediation wave: #2915-#2920, #2925-#2927, #2929), because the
wave deliberately changed what the artifacts measure: the posture grew
from 16 to **18 checks** (#2918 added the boot-refusal env self-attest
check #17 and the FED-RQ-03 pin check #18), the "asi-hard pinned knobs"
row stopped PASSing vacuously under a standard profile (#2927), and the
removal-proof control map grew to **7 rows** including BOTH
`peer_enrolled_in_allowlist` lanes (#2919). They are **not** regenerated
by CI; each is a localhost run of the release-built binary at the tree
this directory is committed to.

## The artifacts

| File | What it records |
|---|---|
| `posture-bare-env.out` | Bare env (`AI_MEMORY_NO_CONFIG=1`, nothing set): exit 2, **8 `[FAIL]` / 10 `[PASS]` of 18**. |
| `posture-hardened-env.out` | Hardened env WITHOUT sqlcipher and WITHOUT the boot gate armed: exit 2, **2 `[FAIL]` / 16 `[PASS]`** (`AI_MEMORY_ENCRYPT_AT_REST` on a non-sqlcipher binary; `AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE` unset). |
| `posture-hardened-boot-refusal.out` | The SAME hardened non-sqlcipher env WITH `AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE=1`: the binary **refuses to boot** (exit 1) naming the one below-floor control — the #2911 item-1 enforcement demonstrated, not merely reported. |
| `posture-sqlcipher-pass.out` | The certified configuration (sqlcipher build, `AI_MEMORY_ENCRYPT_AT_REST=1`, boot gate ARMED): exit 0, **18 `[PASS]` / 0 `[FAIL]`** — boots and passes clean. |
| `removal-proof-full.log` | Full `check-cert-removal-proof.sh` run over the FINAL 7-row control map: **`overall: PASS` — 7/7 `[PROVEN]`**, including both `peer_enrolled_in_allowlist` lanes (write + by-id). This is the full-map PASS log whose absence the 2026-08-12 capture disclosed as finding F5. |
| `removal-proof-firstpass-2026-08-12.log` | The superseded 2026-08-12 first-pass log (pre-remap control map, ends `overall: CERT-RED`). Retained as the rigor trail that forced the remap. |
| `removal-*-{broken,restored}.out` (12) | Per-control mutation pairs re-captured 2026-08-13: one `broken` (control mutated to always-allow → `test result: FAILED`) + one `restored` (reverted → `ok`) per each of the 7 controls (write/by-id/ns-meta/require-push-scope/checkpoint each 1 control; `peer_enrolled_in_allowlist` 2 lanes). |
| `posture-legs-exit-codes.txt` | The four posture legs' observed shell exit statuses (2 / 2 / 1 / 0), recorded because the rendered `.out` files do not themselves print an exit code. |
| `peer-attestation.json`, `peer-fingerprints.txt` | Synthetic fixtures (peer `peer-a`, agent `agent-a`, `team-x/*` namespaces; `peer-a.fleet.example` + an all-`1`s hex). Not real hostnames, keys, or fingerprints. |

The per-control `removal-*-{broken,restored}.out` pairs were
**re-captured at the current tree** (12 files, one broken/restored pair
per control) and are committed alongside the full-map
`removal-proof-full.log`. The two artifacts are complementary, not
redundant: the full-map log records per-control `[PROVEN]` verdicts and
rc (101 broken / 0 restored) across ALL 7 rows in one run; the pairs
carry the per-control cargo output including the specific failing
assertion text under the mutated build. The superseded 2026-08-12 pairs
(from a different tree) were replaced, not merely deleted.

## What was sanitized

| Pattern | Replacement | Files |
|---|---|---|
| Absolute local repo path of the operator checkout | `<repo-root>` | the `AI_MEMORY_FED_PEER_FINGERPRINTS` `actual:` lines in the two hardened/sqlcipher posture legs; cargo `Compiling ai-memory v1.0.0 (…)` banners in the 12 per-control `removal-*-{broken,restored}.out` pairs. (`removal-proof-full.log` is harness verdict rows only — it carries no path and needed no substitution.) |

No other substitutions; verified zero occurrences of the operator
username, hostname, or home path across the bundle after substitution.

## What was NOT present (and therefore not redacted)

- No API keys, passphrases, PEM blocks, or `AI_MEMORY_DB_PASSPHRASE` values.
- No operator home directory beyond the repo path already substituted.
- No live droplet / LAN IPs.

## Integrity anchor

`MANIFEST.sha256` lists every file in this directory except itself and
verifies with `sha256sum -c`. The manifest is not self-authenticating:
its trust anchor is the SSH-signed commit that carries it (the
enrolled-identity signing gate #2486), not the manifest file.

## Producing commit

These artifacts were produced by the release-built `ai-memory 1.0.0`
binary at **`514efdebe453dd3e34aaff7cc3757974490cbc47`** (this document's own committing SHA on
`release/v1.0.0`) — NOT the certification's binding SHA `e22bc93c`,
which predates the posture #17/#18 changes and yields a 16-check
posture. Build at this SHA to reproduce the 18-check / 8-FAIL legs.
