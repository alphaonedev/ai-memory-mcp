# ai-memory CC0 conformance corpus

**License: CC0 1.0 Universal** (`LICENSE` in this directory) — every file in
`conformance/` (vectors, manifest, readers, this README, `ROSETTA.md`) is
dedicated to the public domain so ANY implementation, open or closed, can
embed and run it. This is the falsifiable pass/fail suite of issue #1837
(TRACT gap G24, "the keystone"): the acceptance test for the R24 clean-room
verifier contract in
[`docs/v1.0.0/format-decisions/SIGNABLE-WRITE-V2-AND-VERIFIER-SPEC-DRAFT.md`](../docs/v1.0.0/format-decisions/SIGNABLE-WRITE-V2-AND-VERIFIER-SPEC-DRAFT.md)
§7, and the multi-implementation conformance corpus required by
[Portability Spec v2](../docs/spec/PORTABILITY-V2.md) §V2-5 (#1944).

If you need to decode these bytes with **nothing but a hex dump and this
directory**, start with [`ROSETTA.md`](ROSETTA.md) — the plain-English
decoder-in-archive (#1835).

## Layout

```
conformance/
├── LICENSE                 CC0 1.0 Universal (the whole directory)
├── README.md               this file — what a verifier must do
├── ROSETTA.md              plain-English byte-level decoder (no code needed)
├── manifest.json           machine-readable vector index (see below)
├── vectors/
│   ├── signable_write_v2/      3 unsigned encoding vectors
│   ├── subkey_cert/            1 unsigned encoding vector
│   ├── peer_head_attestation/  2 unsigned encoding vectors
│   ├── signed/                 3 signed vectors (valid / tampered / proof)
│   ├── subkey_chain/           obl. 3 group members (cert→write + self-declared)
│   ├── lineage/                obl. 5 group members (valid / revoked / fork)
│   └── chain/                  obl. 2 group members (intact / deletion / truncation)
└── readers/
    ├── reader.py            Python 3 reference reader (stdlib-only)
    └── reader.mjs           Node.js reference reader (stdlib-only, Node ≥ 19)
```

Every vector file is lowercase hex of the record's exact bytes, one line,
trailing newline.

## Provenance — the vectors are encoder-generated, never hand-authored

Per the format spec's Appendix A discipline, no hex in this corpus was
written by hand. `tests/conformance_corpus.rs` (in the ai-memory repository,
Apache-2.0) regenerates every vector and `manifest.json` from the pinned
in-house encoder (`src/identity/cbor_array.rs` and friends) and CI fails if
the committed corpus drifts from a fresh regeneration. The unsigned vectors
are byte-identical copies of the in-tree golden gate (`tests/golden/**`);
the test asserts that identity too. Signed vectors use fixed, documented
test seeds (they are TEST keys — trusting them outside this corpus would be
an error).

Regenerate after a deliberate, spec-approved format change with:

```
AI_MEMORY_REGEN_GOLDEN=1 cargo test --test conformance_corpus
```

## manifest.json

Top-level fields: `spec`, `spec_doc`, `format_freeze_doc`, `schema_version`
(the ai-memory schema the corpus is anchored to; a Rust test pins it to the
code's `CURRENT_SCHEMA_VERSION`), `generator`, `license`, `domain_tags`
(record-type → frozen domain-tag string), `corpus_digest` (the whole-corpus
SHA-256 integrity anchor — see below), `vectors[]`, and `groups[]` (the
multi-record fixtures — see "Multi-record fixture groups").

Each `vectors[]` entry:

| Field | Meaning |
|---|---|
| `name` | corpus-relative vector id |
| `record_type` | one of `signable_write_v2`, `subkey_cert`, `peer_head_attestation`, `equivocation_proof` |
| `file` | hex file path relative to `conformance/` |
| `domain_tag` | the exact string that MUST appear at element `[0]` |
| `elements` | outer-array element count that MUST match |
| `length_bytes` | byte length of the decoded hex |
| `verdict` | the expected result — see pass criteria below |
| `pubkey` | (signed vectors) raw 32-byte Ed25519 public key, hex |
| `signature` | (detached-signature vectors) raw 64-byte Ed25519 signature over the vector's bytes, hex |

## What a clean-room verifier must do (the spec §7 obligations)

The R24 contract: a **dependency-free, offline, deterministic, sub-10 kLOC**
verifier — no network, no vendor, no model in the loop. The seven numbered
obligations of spec §7, and what this corpus exercises of each:

1. **Re-encode, never decode-and-trust.** Decode any v2 record under the
   restricted CBOR profile (definite-length only; the five allowed shapes:
   uint mt0 / nint mt1 / bytes mt2 / text mt3 / array mt4; floats, simple
   values, tags, maps, `null`, indefinite lengths, and non-shortest-form
   integer heads are all hard rejects), re-encode it through your own
   shortest-form encoder, byte-compare with the original, and check the
   Ed25519 signature over those exact bytes. *Exercised by every vector;
   signature half by `signed/*`.*
2. **Walk the V-4 audit chain** (`prev_hash` + `sequence`) for
   tamper-evidence; with the witness/watermark, detect tail-truncation.
   *Exercised by the `chain/{intact, midchain_deletion, tail_truncation}`
   groups (see "Multi-record fixture groups" below).*
3. **Verify the SubkeyCert→write chain**: cert under the principal root,
   THEN the write under the certified sub-key; reject self-declared
   instances. *Exercised by the `subkey_chain/{valid, self_declared}`
   groups; `subkey_cert/worked_cert` also pins the cert bytes.*
4. **Pin suite→key.** The `suite_tag` inside the signed bytes is
   verification-ADVISORY; the enrolled key is the sole authority. Never
   dispatch the verification algorithm off the wire tag. *BEHAVIORAL: the
   corpus pins tag values 0 and 1 in the write vectors, but the
   key-is-sole-authority rule is verifier policy, not byte-forceable.*
5. **Resolve lineage epoch from the signed succession** for revocation
   windows and equivocation keys; return INDETERMINATE on a stale view.
   *Exercised by the `lineage/{valid, invalid_revoked, equivocation_fork}`
   groups; INDETERMINATE is the byte-forceable equivocation fork.*
6. **Apply the fail-closed visibility allow-list** to any surfaced set.
   *BEHAVIORAL; not byte-exercisable from vectors alone.*
7. **Verify an `EquivocationProof` self-contained and offline**, from the
   subject pubkey inside the proof alone. *Fully exercised by
   `signed/equivocation_proof_real`.*

## Per-vector pass criteria

A conforming reader processes every `vectors[]` entry and reports pass/fail.
For **all** vectors it MUST first: parse the hex; check `length_bytes`;
decode under the restricted profile (rejecting anything outside it,
including trailing bytes); **re-encode and byte-compare** with the original;
check element `[0]` equals `domain_tag` and the outer count equals
`elements`. Then, per `verdict`:

| `verdict` | Additional requirement |
|---|---|
| `reencode-match` | Nothing further. These are bytes-to-be-signed (no signature present). |
| `signature-valid` | `Ed25519.verify(pubkey, signature, vector_bytes)` MUST succeed. |
| `signature-invalid` | The same check MUST **fail** — a reader that accepts this vector is non-conformant. The tampered vector differs from the valid one by a single flipped signature bit. |
| `equivocation-proven` | Decode the 4-element proof envelope; take the 32-byte subject pubkey from element `[1]`; for EACH of the two 6-element attestation entries, re-encode its five committed fields as a `peer_head_attestation` array (prepending that record type's domain tag from `domain_tags`) and verify the entry's 64-byte signature under the subject key over those re-encoded bytes; then require the divergence key — same subject, same epoch, same head_sequence, **different** head_hash. |

Report anything that cannot be checked (e.g. no Ed25519 primitive
available) as an explicit SKIP, never a silent pass.

## Multi-record fixture groups (#1837 obl. 2 / 3 / 5)

Obligations 2, 3, and 5 verify a **relationship across several records** — a
hash chain, a two-link cert→write, a lineage succession — which a single flat
vector cannot express. These live in the manifest's `groups[]` array. Each real
production record is emitted as its own frozen-encoder hex vector under
`vectors/<group>/<role>.hex`; the group's **structure and expectations** live in
the manifest (the answer-key oracle — never hidden in the frozen bytes). A
group carries a `verdict`, an ordered `members[]` list, and an `expected` object
the reader must reproduce EXACTLY. Each member declares its wire `grammar`:

- `array-v2` — the domain-tagged positional array profile above (write / cert).
- `lineage-succession-v1` — a canonical CBOR **map** whose domain is a *signing
  prefix* (`agent-lineage-succession-v1\0`), not an in-body tag.
- `signed-events-chain-v1` — the length-prefixed binary V-4 row encoding;
  `prev_hash` is stored beside the row (in `attrs`), not inside its bytes.

| group `verdict` | Procedure |
|---|---|
| `subkey-chain-verify` | Verify the `cert` member under the principal ROOT (its `pubkey`), then the `write` member under the cert's certified sub-key (cert element `[2]`). A group with **no `cert` member** is a self-declared instance → `expected.outcome = "reject"`, `reject_reason = "self_declared_instance"` (NOT `signature-invalid`: the write's own signature is valid; it fails on chain authorization). |
| `lineage-resolve` | Verify each succession record under its predecessor over `LINEAGE_DOMAIN ‖ body`; resolve a THREE-valued `expected_state`: an **equivocation fork** (two successors at one `epoch` under one `predecessor_pubkey`) → `indeterminate`; a `revocation` record → `invalid-revoked`; else `valid`. `resolution_policy` fixes the indeterminate/invalid boundary so it is corpus-defined, not reader-chosen. |
| `chain-verify` | Walk the V-4 chain: each row's `prev_hash` must equal SHA-256 of the prior row's canonical bytes and `sequence` must be consecutive (a gap + mismatch → `break_kind = "midchain-deletion"`); a surviving `MAX(sequence)` below the off-table `witness_head_sequence` watermark → `tail-truncation`; otherwise `intact` / `none`. |

The manifest's top-level **`corpus_digest`** is a single SHA-256 over every
vector + group-member record (keyed by file path, pre-image
`path ‖ 0x00 ‖ bytes ‖ 0x00`, sorted). A reader recomputes it over the
referenced files and MUST reject the corpus on mismatch — this binds the
unsigned answer-key oracle to the frozen record bytes so neither can drift.

## Reference readers

Both readers are deliberately minimal (a few hundred lines), dependency-free
translations of the pass criteria above. They are **references, not the
product**: read them to disambiguate the prose, then write your own.

```
python3 readers/reader.py                       # structure + re-encode; sig checks SKIP
python3 readers/reader.py --verify-signatures   # + Ed25519 via optional pyca 'cryptography'
node readers/reader.mjs                         # everything, incl. Ed25519 (WebCrypto, Node ≥ 19)
```

Capability matrix:

| Check | reader.py | reader.py --verify-signatures | reader.mjs |
|---|---|---|---|
| Profile-restricted decode + shortest-form enforcement | ✅ | ✅ | ✅ |
| Re-encode + byte-compare (§7.1) | ✅ | ✅ | ✅ |
| Domain-tag + element-count + length pins | ✅ | ✅ | ✅ |
| Detached Ed25519 verify (valid + MUST-reject) | SKIP¹ | ✅² | ✅ |
| Equivocation proof: divergence-key checks | ✅ | ✅ | ✅ |
| Equivocation proof: embedded signature verify | SKIP¹ | ✅² | ✅ |
| `corpus_digest` whole-corpus integrity anchor | ✅ | ✅ | ✅ |
| Group resolution: chain-verify (obl. 2) | ✅ | ✅ | ✅ |
| Group resolution: subkey-chain / lineage structure (obl. 3 / 5) | ✅ | ✅ | ✅ |
| Group signatures: subkey-chain + lineage Ed25519 | SKIP¹ | ✅² | ✅ |

¹ CPython's stdlib has no Ed25519; this project vendors no cryptographic
code (the sole-authority rule), so the pure-stdlib run reports signature
checks as SKIP and still enforces every structural obligation.
² Via the optional third-party [pyca `cryptography`](https://cryptography.io)
package, loaded only under the explicit flag.

## Corpus coverage (honest scope)

This corpus covers the v2 signed-record FORMAT family end-to-end **and** the
byte-exercisable spec-§7 obligations, via the single vectors above plus the
multi-record `groups` (#1837):

- **Obligations 1 + 7** — re-encode-never-decode-and-trust and the offline
  equivocation proof — fully exercised by the single vectors.
- **Obligation 2** — the V-4 audit chain — the `chain/{intact,
  midchain_deletion, tail_truncation}` groups.
- **Obligation 3** — the SubkeyCert→write chain, incl. the self-declared
  negative — the `subkey_chain/{valid, self_declared}` groups.
- **Obligation 5** — lineage epoch / revocation / INDETERMINATE — the
  `lineage/{valid, invalid_revoked, equivocation_fork}` groups.

**Obligations 4 and 6 remain BEHAVIORAL — not vector-forceable.** Obligation 4
(pin suite→key: the enrolled key is the sole authority, the wire `suite_tag` is
advisory) and obligation 6 (apply the fail-closed visibility allow-list to any
surfaced set) are verifier-runtime policies, not properties of a static record.
A corpus of bytes cannot force them; they are the implementer's contract.

**Remaining residue** — one fixture, tracked under **#1944** (v1.x):

- an **L1/L2/L3 export-envelope round-trip fixture** for Portability v2 §V2-5's
  data-plane half. The envelope FORMAT is frozen (PORTABILITY-V2 §V2-4, schema
  v80), but the v2-envelope PRODUCER (`ai-memory export`'s portability path) is
  deferred to v1.x under #1944 — `ai-memory export` today is a memories+links
  convenience view, not the portability exporter — so this fixture cannot be
  encoder-generated under the same drift-gated discipline as its siblings until
  that producer lands. It is intentionally NOT hand-authored.

All groups are additive — they change no frozen bytes.
