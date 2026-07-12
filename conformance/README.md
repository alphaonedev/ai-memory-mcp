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
│   └── signed/                 3 signed vectors (valid / tampered / proof)
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
(record-type → frozen domain-tag string), and `vectors[]`.

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
   *NOT exercised by this corpus revision — needs a signed-events chain
   fixture (see "Corpus residue" below).*
3. **Verify the SubkeyCert→write chain**: cert under the principal root,
   THEN the write under the certified sub-key; reject self-declared
   instances. *Partially exercised: `subkey_cert/worked_cert` pins the cert
   bytes a verifier must re-encode; the full two-link chain fixture is
   residue.*
4. **Pin suite→key.** The `suite_tag` inside the signed bytes is
   verification-ADVISORY; the enrolled key is the sole authority. Never
   dispatch the verification algorithm off the wire tag. *Structural: the
   corpus pins tag values 0 and 1 in the write vectors; behavior is on the
   implementer.*
5. **Resolve lineage epoch from the signed succession** for revocation
   windows and equivocation keys; return INDETERMINATE on a stale view.
   *Behavioral; the proof vector carries the epoch field a resolver keys on.*
6. **Apply the fail-closed visibility allow-list** to any surfaced set.
   *Behavioral; not byte-exercisable from vectors alone.*
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

¹ CPython's stdlib has no Ed25519; this project vendors no cryptographic
code (the sole-authority rule), so the pure-stdlib run reports signature
checks as SKIP and still enforces every structural obligation.
² Via the optional third-party [pyca `cryptography`](https://cryptography.io)
package, loaded only under the explicit flag.

## Corpus residue (honest scope)

This corpus revision covers the v2 signed-record FORMAT family end-to-end
(obligations 1 and 7 fully; 3 partially). A complete R24 acceptance suite
still needs, tracked under #1837:

- a **signed_events V-4 chain fixture** (multi-record: intact chain, a
  middle-deletion break, a tail truncation + witness watermark) for
  obligation 2;
- a **two-link SubkeyCert→write chain vector** (root key, cert, write signed
  by the certified sub-key, plus a self-declared-instance negative) for
  obligation 3;
- **lineage succession vectors** (epoch walk, a revocation record, a
  stale-view INDETERMINATE case) for obligation 5;
- an **L1/L2/L3 export-envelope round-trip fixture** (a small NDJSON/JSON
  export with signed classes) for Portability v2 §V2-5's data-plane half.

None of these change frozen bytes — they extend the corpus additively.
