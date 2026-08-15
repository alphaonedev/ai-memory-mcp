# ai-memory federation lab — laptop reproducibility kit

Stand up a real, hardened, two-node **ai-memory v1.0.0 federation** on your own
laptop with one command, load a synthetic corpus, and watch the
kit prove — with assertions, not adjectives — that an attested write on one
node replicates across a mutually authenticated TLS mesh and is recallable on
the other, while an unpinned client, a plaintext client, and an unsigned write
are all refused.

```bash
cd infra/federation-lab
./run.sh
```

No cloud account, no Docker, no network egress, no `/tmp`, no `sudo`. It
writes only inside this directory and removes what it wrote when it exits.

---

## Table of contents

- [What you get](#what-you-get)
- [Prerequisites](#prerequisites)
- [Running it](#running-it)
- [What each step does](#what-each-step-does)
- [Expected output](#expected-output)
- [The asi-hard 16/17 caveat, stated honestly](#the-asi-hard-1617-caveat-stated-honestly)
- [The corpus](#the-corpus)
- [What this does and does not prove](#what-this-does-and-does-not-prove)
- [Troubleshooting](#troubleshooting)
- [How this relates to the production kit](#how-this-relates-to-the-production-kit)

---

## What you get

A two-node federation on loopback:

```
        node-a  https://127.0.0.1:19481          node-b  https://127.0.0.1:19482
        ├─ server cert  peerA.crt                ├─ server cert  peerB.crt
        ├─ allowlist    SHA-256(peerB.crt)  ◄────┤  presents peerB.crt as client
        ├─ presents peerA.crt as client   ───────►  allowlist  SHA-256(peerA.crt)
        ├─ fed identity ai:lab-node-a             ├─ fed identity ai:lab-node-b
        │   (peer's public half enrolled)         │   (peer's public half enrolled)
        ├─ 16/17 asi-hard knobs at hard floor     ├─ 16/17 asi-hard knobs at hard floor
        ├─ attestation REQUIRED                   ├─ attestation REQUIRED
        └─ 300 synthetic corpus rows              └─ (receives the replicated write)
                         └──────── quorum W=2, mutual TLS ────────┘
```

Both nodes trust each other by **certificate fingerprint**, not by CA. The
kit's `client-bad.crt` is signed by the *same* certificate authority as every
other leaf and is still refused — that negative is the whole point: the pin is
the trust anchor, the CA is not.

---

## Prerequisites

| Tool | Why |
| --- | --- |
| `openssl` | mints the CA + leaf certificates (via the prior-art generator) |
| `curl` | drives the HTTPS/mTLS surface |
| `jq` | builds and reads JSON bodies |
| `sqlite3` | reads each node's own database — the receiver's ground truth |

`python3` is **not** required to run the lab. It is needed only to regenerate
the committed synthetic fixture (`tools/make-synthetic-corpus.sh`), which a lab
user never has to do.

```bash
# Debian / Ubuntu
sudo apt-get install -y openssl curl jq sqlite3
# macOS
brew install openssl curl jq sqlite
```

Plus an `ai-memory` binary and the `attest_sign` example. From a checkout:

```bash
cargo build --release --bin ai-memory --example attest_sign
```

`run.sh` finds them in `target/release/` automatically; `--bin` / `--signer`
override. The signer is not optional and not replaceable by a shell script:
the lab signs its attested write with the **same crate code the daemon
verifies with**, so the canonical CBOR bytes are never re-implemented in bash.

**No network access is required.** The nodes run at `tier = "keyword"`, so
they never load or download an embedding model.

---

## Running it

```bash
./run.sh                          # the whole thing
./run.sh --keep                   # keep run/ afterwards for a post-mortem
./run.sh --port-a 20481 --port-b 20482
./run.sh --corpus-db /path/to/your.db     # seed YOUR local corpus instead of the fixture
./run.sh --recall-query 'kiln rotation'   # choose the corpus-recall proof query
./run.sh --no-caveat-probe        # skip the asi-hard 17/17 cold-boot demonstration
./run.sh --help
```

Exit code `0` means every assertion passed. Any non-zero exit means at least
one `FAIL` row is printed above the summary, and the summary lists them again.

`run.sh` is **idempotent**: it deletes and recreates `run/` at the start of
every invocation, so a crashed previous run leaves nothing behind that can
change the next one. It is also self-cleaning: an `EXIT`/`INT`/`TERM` trap
stops every daemon it started and (absent `--keep`) removes `run/`.

---

## What each step does

### 0 · preflight

Checks the five tools, resolves the binary and the signer, refuses to start if
either lab port is already bound, and then runs the **posture drift guard**:
`lib/posture.sh::lab_posture_ssot_check` re-parses `src/security_profile.rs::KNOBS`
and asserts the lab's knob list is exactly the SSOT's, minus the one documented
omission. If the code grows an eighteenth pinned knob, this step goes red
rather than quietly demonstrating a posture that no longer exists. (Running
from a release tarball with no `src/` tree, the check reports "skip" — it
cannot verify, and says so, rather than passing.)

### 1 · workspace

Creates `run/` with a private `HOME` per node. Each node's `config.toml` sets
`tier = "keyword"`.

> **Why a private `HOME` and not `XDG_CONFIG_HOME`:** the config resolver
> (`AppConfig::config_path`) reads `$HOME/.config/ai-memory/config.toml` and
> **ignores `XDG_CONFIG_HOME`** — the same gotcha `infra/do-hive/cloud-init-memory.yaml.tpl`
> documents as #2852, where a config written to the XDG path was never read and
> the daemon fail-closed on a bind. Step 6 asserts the daemon logged
> `loaded config from …`, so an inert override is caught rather than assumed.

### 2 · crypto material

Calls **`infra/do-hive/crypto/gen-certs.sh`** with `OUT_DIR=run/crypto`. This
kit does not mint its own certificates. The prior-art generator's comments
encode hard-won constraints that are preserved by calling it rather than
copying it — most notably that the chain is **RSA/SHA-256, not Ed25519**,
because an Ed25519 certificate carries no separate digest OID and libpq aborts
a `verify-full` + SCRAM channel-binding handshake with
`could not find digest for NID UNDEF`. rustls accepts RSA leaves happily, so
one chain serves every leg.

Produces `ca.{crt,key}`, `server.*`, `client-good.*`, `client-bad.*`,
`peerA.*`, `peerB.*`, per-peer allowlists, and `fingerprints.txt`.

### 3 · identities, cross-peer enrollment, agent key binding

Each node gets a federation identity (`ai:lab-node-a` / `ai:lab-node-b`) and
enrolls the other's public half, so the always-on v1.0.0 transport gates
(`FED_REQUIRE_SIG`, `FED_REQUIRE_NONCE`, `FED_REQUIRE_PEER_ENROLLMENT`) are
satisfied by **real enrollment, not an escape hatch**.

The author identity `ai:lab-author` is registered and its public key **bound on
both node databases** — the receiving node has to be able to verify the
author's signature on a relayed write, and it can only do that against a key it
holds locally.

> **Known flake #2941 is guarded here, loudly.** `agents bind-key` has been
> observed to silently no-op on a fresh database (~1 run in 4 in the reported
> repro): the registry row is created but `metadata.agent_pubkey` is never set,
> and every subsequent signed write then returns `403 ATTESTATION_FAILED` — a
> failure that *looks* like broken attestation but is broken enrollment.
> `agents list` does not expose the pubkey, so the standard check cannot see
> it. The lab therefore binds, then **reads the key back out of the `_agents`
> registry row**, retries up to three times, and fails with an explicit pointer
> to #2941 if it never lands. If you hit it, attach `run/node-*/daemon.log` and
> the attempt count to that issue.

### 4 · seed the corpus

Imports the committed synthetic corpus (or your `--corpus-db` slice) into
node A. **This runs in an unhardened bootstrap phase,
and the kit says so out loud.** Under the hardened posture every direct write
must be attested, so a corpus cannot be bulk-loaded through the hardened
surface — and should not be: this is the offline provisioning phase a real
deployment performs before the node ever listens. "The corpus was seeded under
a weaker posture than it is served under" is exactly the kind of thing a reader
deserves to be told rather than left to infer.

### 5 · asi-hard posture

Prints the exact knob set (also written to `run/evidence/posture.env`), then —
unless `--no-caveat-probe` — **demonstrates** the 17th-knob caveat instead of
merely asserting it: it cold-boots a throwaway node under the full
`AI_MEMORY_SECURITY_PROFILE=asi-hard` profile on a fresh database and records
the actual exit code and stderr into
`run/evidence/caveat-asi-hard-coldboot.txt`. See the next section.

### 6 · launch the two-node mTLS federation

Two `ai-memory serve` processes, each with `--tls-cert` / `--tls-key` /
`--mtls-allowlist` and `--quorum-writes 2 --quorum-peers https://127.0.0.1:<other>`,
fanning writes to each other with their own cert as the outbound client cert
and verifying the peer's server cert against the shared CA. Topology and flag
set follow `infra/do-hive/crypto/test-federation-mtls.sh`, including its
generous health-poll window (a boot race under machine load was a real prior
failure, documented in `infra/do-hive/crypto/KNOWN-DO-STAGING.md` §2).

### 7 · negative lanes

| | Assertion |
| --- | --- |
| **N1** | A cert signed by the *same CA* but absent from the allowlist is refused at the TLS layer. |
| **N2** | Plaintext `http://` against the mTLS port is refused. |
| **N3** | An unsigned write returns `403` under `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1`. |
| **N4** | `asi-hard` **refuses to boot** when a pinned knob is set below its hard floor — the no-disable contract that makes the posture a posture and not a suggestion. |

### 8 · positive lanes

| | Assertion |
| --- | --- |
| **P1** | A signed write is accepted at node A. |
| **P2** | Node A stored it at `attest_level = agent_attested` — attested, not merely accepted. |
| **P3** | The write **replicated to node B** over the quorum channel and arrived `agent_attested`. Read from node B's own database, which is the receiver's ground truth and sidesteps the #1468 private-scope read filter. |
| **P4** | **Federated recall** — node B, which never saw the original request, returns the memory. |
| **P5** | Corpus recall on node A returns hits from the seeded namespace. The run states whether the query was fixture-authored or derived from your corpus. |

### 9 · run manifest

`run/evidence/manifest.txt` records the binary, its version, the host, the
ports, the corpus provenance and row count, the posture, and the tally.

---

## Expected output

The closing summary of a real green run on this machine
(`ai-memory 1.0.0`, Linux x86_64):

```
══ SUMMARY 
   PASS asi-hard posture list matches src/security_profile.rs::KNOBS — ok: lab posture covers all 17 SSOT knobs (16/17 at hard floor, 1 omitted per #2942)
   PASS gen-certs.sh minted the CA + peer/client leaves into run/crypto
   PASS cross-peer federation identities enrolled (ai:lab-node-a ↔ ai:lab-node-b)
   PASS node-a: author pubkey bound AND read back from the _agents registry row (#2941 guard, attempt 1)
   PASS node-b: author pubkey bound AND read back from the _agents registry row (#2941 guard, attempt 1)
   PASS node-a seeded with 300 rows in namespace 'lab-corpus', all unexpired (from the committed SYNTHETIC fixture lab-corpus.json; file declares 300)
   PASS caveat demonstrated: full 17-knob asi-hard cold boot on a fresh DB exited 75 naming the rollback check (issue #2942) — evidence in run/evidence/caveat-asi-hard-coldboot.txt
   PASS both nodes answer /api/v1/health over mutual TLS with a PINNED client cert
   PASS node-a loaded its private config (tier=keyword) — no embedder, no network
   PASS N1 unpinned client cert refused at node-b's TLS layer (same CA, absent from the allowlist)
   PASS N2 plaintext http refused at node-b's mTLS port
   PASS N3 unsigned write refused 403 ATTESTATION_FAILED under AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1
   PASS N4 asi-hard REFUSED to boot with a loosened pin (exit 1, names AI_MEMORY_SECRET_SCREEN_MODE) — the no-disable contract holds
   PASS P1 attested write accepted at node-a (HTTP 201, id=…)
   PASS P2 node-a stored it at attest_level=agent_attested (signature verified against the bound key)
   PASS P3 the write REPLICATED to node-b over the mTLS quorum channel and arrived agent_attested
   PASS P4 federated recall: node-b returns the memory that was written to node-a
   PASS P5 corpus recall on node-a returned 5 result(s) from 'lab-corpus' (lexical — tier=keyword, query fixture-authored)

   18 PASS / 0 FAIL

   federation lab GREEN — 18 assertions passed.
```

The assertion count is not a fixed constant — it is however many rows the run
actually emitted. What matters is `0 FAIL` and exit code `0`.

---

## The asi-hard 16/17 caveat, stated honestly

The certified enterprise-federation posture is **`asi-hard`**
(`AI_MEMORY_SECURITY_PROFILE=asi-hard`, rendered for operators as
`docs/deploy/asi-hard.env`, SSOT `src/security_profile.rs::KNOBS`). It pins
**seventeen** security knobs to a hard floor and refuses to boot if any of them
is set *below* that floor — the "no-disable" contract.

**This lab runs sixteen of the seventeen, and does not set the profile knob.**

The seventeenth, `AI_MEMORY_REQUIRE_ROLLBACK_CHECK`, **cannot cold-boot a fresh
node.** In require-mode the open-time rollback-evidence check treats an absent
off-table head anchor as refuse-to-open, and that anchor is emitted only by the
witness watermark cadence over the `signed_events` chain — which is empty on a
brand-new database. Fresh DB → no anchor → **exit 75**. This is tracked as
[**issue #2942**](https://github.com/alphaonedev/ai-memory-mcp/issues/2942)
(open as of 2026-08-15), filed from the v1.0.0 federation-config assessment.

Because the profile knob's contract is *pin and refuse*, there is no such thing
as "asi-hard with rollback-check off": setting the profile **and** lowering one
pin is precisely the case the profile refuses. So the lab sets the sixteen
satisfiable knobs to their hard-floor values directly and leaves
`REQUIRE_ROLLBACK_CHECK` at its safe default (emit-evidence-and-continue). That
is the same 16/17 shape a persistent hive node runs today.

Two of the seventeen are *permissive* hatches whose hard floor is "unset"
(`AI_MEMORY_ALLOW_SCHEMA_AHEAD`, #2445; `AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS`,
#2477). The lab actively **unsets** them rather than inheriting whatever the
operator's shell exported — an inherited hatch is exactly the silent weakening
the posture exists to prevent.

The kit does not ask you to take any of this on faith:

- **Step 0** re-derives the pinned set from the Rust SSOT and fails on drift.
- **Step 5** cold-boots a throwaway node under the *full* 17-knob profile and
  records the real exit code, so the caveat is demonstrated rather than
  asserted. If that boot ever succeeds — i.e. #2942 is fixed on your build —
  the kit says so loudly and tells you this README is now stale.
- **Step 7 N4** proves the no-disable contract is real by trying to loosen a
  pin under the profile and asserting the refusal.

---

## The corpus

`sample/lab-corpus.json` is a **300-row synthetic corpus** (namespace
`lab-corpus`), committed so the lab has something real to query with no
download and no network. Every row is generated: deterministically composed,
obviously fictional prose about an invented freight cooperative on an invented
coastline. Each row carries `metadata.synthetic = true`, so a row that ever
escapes into a real corpus is still self-identifying.

**Why synthetic, and not a slice of a real corpus.** This repository is
**public**. Committing a verbatim slice of a real third-party corpus is
redistribution of that corpus — the size of the slice and whether the
embedding vectors ride along are irrelevant to the rights question — and it
republishes someone else's text, attribution-free, under this project's name.
It also drags along whatever identifiers the source rows happened to carry: an
internal `metadata.agent_id`, or a `version_vector` keyed by the hostname of
the machine that generated them. Synthetic fixtures are this repo's house
standard for committed data for exactly these reasons; see PR #2926, which
re-minted the golden/conformance vectors from synthetic identities.

Regenerate the fixture with `tools/make-synthetic-corpus.sh` (needs `python3`,
which the lab itself does not). It is fully deterministic — ids are UUIDv5 over
a fixed namespace and the row index, timestamps are a constant, the vocabulary
is drawn with a seeded PRNG — so a reviewer can regenerate and `diff` rather
than take the artifact on trust. There is no hostname, no machine identity and
no wall-clock anywhere in the output.

### Running against your own corpus

```bash
./run.sh --corpus-db /path/to/your.db --corpus-ns your-namespace
```

`--corpus-db` builds a slice through `tools/make-local-slice.sh` into the run
directory, seeds it, and deletes it on exit. **That output is never
committed**: the tool's default path is `sample/local/`, which this directory's
`.gitignore` excludes, and `run.sh` writes its slice under `run/`, which is
ignored and removed on exit. Keeping a real corpus on your machine and out of
git is the whole point of the split between the two tools.

With `--corpus-db` and no `--recall-query`, the lab **derives** the recall query
from a seeded title. That is a weaker proof than an authored query — it shows
the FTS index, the query path and the visibility filter all work end to end, but
not that the corpus answers a question posed independently of it — so the run
labels which kind it used instead of presenting them as equivalent. Pass
`--recall-query` for the stronger form.

> **Both fixtures are stamped long-tier on purpose, and that is not cosmetic.**
> A committed fixture must not depend on how long ago it was generated. Rows at
> `tier = mid` carry a 7-day TTL applied at *write* time — so importing a slice
> whose `created_at` is two weeks old lands rows that are **already expired**.
> They are present in `memories` (a `COUNT(*)` cheerfully says 300, which is
> exactly why this is easy to miss), but recall filters on
> `expires_at IS NULL OR expires_at > now` and returns nothing, and the next gc
> tick archives them out from under the run. Both the synthetic generator and
> the local-slice tool therefore stamp `tier = long` — permanent, no TTL,
> whatever `created_at` says — and `make-local-slice.sh` preserves the original
> tier in `metadata.sample_source_tier`. Step 4 additionally asserts every
> seeded row is **unexpired**, not merely present, so this failure mode can
> never again present itself as "recall is broken".

> **Caveat F-L8a — recall quality depends on the embedder.** Neither fixture
> carries embedding vectors: the synthetic corpus never had any, and
> `make-local-slice.sh` strips them. A vector is only meaningful against the
> embedder that produced it, and the lab's nodes run at `tier = "keyword"` (no
> embedder, no network), so feeding another embedder's vectors into them would
> be feeding in numbers nobody can interpret. **The lab's recall lane is
> therefore lexical**, and its assertions are about federation, attestation and
> mTLS — not about semantic ranking quality. Nothing in this kit measures, or
> should be read as measuring, retrieval relevance.
>
> To exercise the semantic lane, point `--corpus-db` at a full local corpus
> **and make sure the node's configured embedder matches the one that produced
> its vectors**. A mismatch is exactly the same-dimension-different-space
> hazard `AI_MEMORY_REQUIRE_EMBED_MODEL_MATCH` (#2167) exists to catch.

---

## What this does and does not prove

Labelled, because a reproducibility kit that overclaims is worse than none.

**Established** — directly asserted by this kit on your machine, and the run
goes red if any of it stops being true:

- Two v1.0.0 nodes federate over mutual TLS with fingerprint-pinned peers.
- A same-CA certificate that is not on the allowlist is refused; plaintext is
  refused.
- With attestation required, an unsigned write is refused and a properly signed
  write is accepted and stored `agent_attested`.
- That attested write replicates to the peer and arrives `agent_attested`, and
  the peer returns it from `recall`.
- The `asi-hard` no-disable contract refuses a boot with a loosened pin.
- Sixteen of the seventeen pinned knobs boot cleanly together on a fresh node.
- The seventeenth does not (issue #2942) — demonstrated, with its exit code
  captured.

**Plausible** — consistent with what the kit shows, but *not* measured here:

- That the same configuration behaves this way on more than two nodes, or on
  hosts that are not loopback. The topology is identical to the production
  hive's (same flags, same certificate shapes), which is why the extrapolation
  is reasonable — but this kit does not test it.

**Unverified / out of scope** — do not read this kit as evidence for any of it:

- **Performance, throughput, latency, or capacity of any kind.** Two processes
  on one laptop measure nothing about a fleet, and the kit deliberately reports
  no timings.
- Retrieval relevance or semantic recall quality (see F-L8a above). The default
  corpus is synthetic, so the recall step proves the pipeline works — not that
  it works well on your data.
- Postgres-backed nodes. The default path is SQLite; the Postgres/AGE/pgvector
  leg is exercised by `infra/do-hive/crypto/test-pg-verifyfull.sh`, not here.
- At-rest encryption. These nodes are not sqlcipher builds, so
  `ai-memory doctor --posture enterprise-federation` would not pass on them —
  that posture requires at-rest encryption, and the lab does not claim it.
- Any durability property beyond `AI_MEMORY_DB_SYNCHRONOUS=FULL` being set.

**Certification scope.** The v1.0.0 enterprise-federation certification is
scoped to **500–1,000 agents and at most 50 peers**
(`docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md` §6). Nothing in this
kit extends that scope, and nothing here should be quoted as if it did.

---

## Data-tier versions

The lab's default path is SQLite and pins nothing in the data tier. If you take
the Postgres leg (`infra/do-hive/crypto/test-pg-verifyfull.sh`, or a production
hive node), the locked stack is:

| Component | Pinned version |
| --- | --- |
| PostgreSQL | **18.6** |
| Apache AGE | **1.8.0** |
| pgvector | **0.8.6** |

**On the AGE version, both surfaces, stated together** — because they disagree
and the disagreement confuses people:

- `github.com/apache/age/releases` carries **PG18 / v1.8.0-rc0 (2026-07-09)**,
  which is the newest released AGE for PostgreSQL 18.
- Apache tags **every** release `X.Y.Z-rc0` — that is the ASF release-vote
  convention, not a pre-release marker. Consequently pgdg reads the package as
  `1.8.0~rc0-…` while `extversion` reports plain `1.8.0`.
- The download page `age.apache.org/download` **lags**, still showing 1.7.0.

The `~rc0` suffix is **not** a Debian packaging revision. That claim is false
and was purged from PR #2940; do not reintroduce it.

---

## Troubleshooting

**`missing required tool(s): …`** — install the listed packages; the message
carries the apt/brew lines.

**`port 19481 is already in use`** — another process (often a previous lab run
that was `kill -9`'d) holds it. `./run.sh --port-a 20481 --port-b 20482`, or
find the holder with `ss -ltnp | grep 19481`.

**`no ai-memory binary found`** — `cargo build --release --bin ai-memory --example attest_sign`,
or pass `--bin` / `--signer`.

**`agents bind-key silently no-opped`** — issue #2941, described in step 3
above. Re-run; if it reproduces, that is useful data for the issue.

**`one or both nodes never became reachable`** — read
`run/node-a/daemon.log` and `run/node-b/daemon.log` (re-run with `--keep` so
they survive). The most common causes are a stale certificate directory from an
interrupted run (fixed by re-running, which wipes `run/`) and a host under
enough load that boot exceeded the 60-second poll window.

**`P3 the write never reached node-b`** — replication failed. Check node B's
log for `write.?sig` / `enroll` / `quorum` lines. The usual cause is the author
key not being bound on node B, which step 3's #2941 guard should have caught
first.

**`node-a did not load its private config`** — the #2852 shape: the config
resolver reads `$HOME/.config/ai-memory/config.toml` only. If you have
overridden `HOME` in your shell in a way that survives into the subshell, the
node may be reading a different file.

**Everything failed at once** — check that you are running the kit from a
checkout whose `infra/do-hive/crypto/gen-certs.sh` exists and is executable;
step 2 exits early and says so if not.

---

## How this relates to the production kit

This lab **extends** the DigitalOcean hive crypto suite rather than forking it:

| Prior art | How the lab uses it |
| --- | --- |
| `infra/do-hive/crypto/gen-certs.sh` | **Called directly.** All certificates, keys, allowlists and fingerprints come from it. |
| `infra/do-hive/crypto/test-federation-mtls.sh` | Topology, port/flag layout and pos/neg shapes for the mTLS quorum mesh. |
| `infra/do-hive/crypto/test-fed-write-sig-attestation.sh` | Cross-peer identity enrollment, author key binding on both databases, and reading the receiver's own database as ground truth. |
| `infra/do-hive/crypto/test-attestation.sh` | The signed/unsigned write pair and the `attest_sign` example as signer. |
| `infra/do-hive/crypto/run-all-local.sh` | The "one script, every leg, non-zero on any failure" shape. |
| `infra/do-hive/crypto/KNOWN-DO-STAGING.md` | The boot-race poll window that the lab keeps. |

If you want the **full** local suite — including the Postgres `verify-full` +
SCRAM channel-binding leg and the semantic-recall leg — run
`infra/do-hive/crypto/run-all-local.sh`. This lab is the narrower,
stranger-friendly, one-command front door to the same substrate.
