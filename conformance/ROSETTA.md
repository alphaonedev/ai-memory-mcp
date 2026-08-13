# ROSETTA — how to read ai-memory signed records with nothing but this file

<!-- SPDX-License-Identifier: CC0-1.0 -->

This is the **decoder-in-archive** (issue #1835, TRACT gap G21): a
self-contained, plain-English specification of the bytes in this corpus —
and of every "v2 family" signed record an ai-memory export carries — written
so that a reader **decades from now, with no running ai-memory binary, no
Rust toolchain, and no internet**, can interpret the bytes. You need only:
a hex dump of the record, this file, and (to check signatures) any
implementation of Ed25519 (RFC 8032) — a public, stable, widely reimplemented
algorithm.

Everything here is public domain (CC0, see `LICENSE`).

---

## 1. The one encoding rule

Every v2 signed record is a **CBOR definite-length array** (CBOR is IETF
RFC 8949, a public standard; but this file explains the needed subset from
scratch so you don't need the RFC).

A CBOR item starts with one **head byte**. Its top 3 bits are the *major
type*; its low 5 bits are the *argument info*:

```
head byte = (major_type << 5) | info
```

Only FIVE major types ever appear in a v2 record:

| Major | Head-byte range | Meaning | Argument means |
|---|---|---|---|
| 0 | `0x00–0x1b` | unsigned integer | the value itself |
| 1 | `0x20–0x3b` | negative integer | value is `-1 - argument` |
| 2 | `0x40–0x5b` | byte string | length in bytes; raw bytes follow |
| 3 | `0x60–0x7b` | UTF-8 text | length in bytes; text bytes follow |
| 4 | `0x80–0x9b` | array | element count; elements follow |

The argument is read from `info`:

| `info` | Argument |
|---|---|
| 0–23 | the info value itself (inline) |
| 24 (`0x18`) | next 1 byte |
| 25 (`0x19`) | next 2 bytes, big-endian |
| 26 (`0x1a`) | next 4 bytes, big-endian |
| 27 (`0x1b`) | next 8 bytes, big-endian |

**Profile restrictions (rejects, not options):** every length is definite
(info 31 never appears); every integer/length uses the SHORTEST form that
fits (23 is never encoded as `0x18 0x17`); major types 5 (map), 6 (tag), and
7 (floats / `true` / `false` / `null`) never appear. If you see any of them,
the record is not a well-formed v2 record. There is exactly ONE valid
encoding of any record, which is why signatures can be checked by
*re-encoding*: rebuild the bytes from the decoded fields using these rules
and they must match the original exactly.

**Optional fields** cannot be omitted from a positional array, so they are
wrapped: `[0]` (a 1-element array holding the integer 0) means ABSENT;
`[1, value]` means PRESENT. An absent string is NOT the same as an empty
string — the two encode differently by design.

## 2. Domain tags — element [0] names the record type

Element `[0]` of every record is a text string that both *identifies* and
*version-stamps* the record type. It is inside the signed bytes, so a record
of one type can never be replayed as another. The frozen registry:

| Domain tag (exact string) | Record | Outer elements |
|---|---|---|
| `ai-memory/write/v2` | SignableWrite v2 — a memory write's signed identity | 11 |
| `ai-memory/subkey-cert/v1` | SubkeyCert — principal root certifies a per-instance sub-key | 6 |
| `ai-memory/peer-head-attestation-v1` | a subject-signed claim "my audit chain head at sequence S is hash H" | 6 |
| `ai-memory/equivocation-proof/v1` | two conflicting head-attestations + the subject's public key | 4 |
| `ingestion-v1` | dormant weight-ingestion event (reserved; no live records yet) | 6 |
| `ai-memory/recall-attestation/v1` | RESERVED for a future read-path record; none exist at v1.0 | — |

## 3. Field maps

### 3.1 `ai-memory/write/v2` (11 elements)

| # | Field | CBOR shape | Notes |
|---|---|---|---|
| 0 | domain tag | text | `"ai-memory/write/v2"` |
| 1 | agent_id | text | who claims the write |
| 2 | namespace | text | |
| 3 | title | text | already secret-screened |
| 4 | memory_kind | text | closed vocabulary (`observation`, `instruction`, …) |
| 5 | created_at | text | RFC 3339 timestamp |
| 6 | content_digest | bytes | a **multihash** — see §4 |
| 7 | instance_key_id | bytes | 32 raw bytes — the signing sub-key's Ed25519 public key |
| 8 | model_version_ref | bytes | reference to the signer's model attestation |
| 9 | session_id | array | presence-wrapped optional text (§1) |
| 10 | suite_tag | uint | `0` = Ed25519+SHA-256. ADVISORY — never pick your verify algorithm from it |

### 3.2 `ai-memory/subkey-cert/v1` (6 elements)

`[0]` domain tag · `[1]` principal (text) · `[2]` instance_key_id (bytes,
the certified sub-key) · `[3]` model_version_ref (bytes) · `[4]` not_before
(text, RFC 3339) · `[5]` not_after (text). Signed by the **principal root**
key; a write is trustworthy only if its sub-key is certified by a valid cert.

### 3.3 `ai-memory/peer-head-attestation-v1` (6 elements)

`[0]` domain tag · `[1]` subject_agent_id (text) · `[2]` epoch (uint) ·
`[3]` head_sequence (uint) · `[4]` head_hash (bytes, 32) · `[5]` signed_at
(text). Signed by the **subject's own** key: "at sequence S of my audit
chain, in key-epoch E, my head hash is H."

### 3.4 `ai-memory/equivocation-proof/v1` (4 elements)

`[0]` domain tag · `[1]` subject_pubkey (bytes, 32 — the subject's raw
Ed25519 public key) · `[2]` attestation_a · `[3]` attestation_b.

Each attestation is a **6-element inner array** — the FIVE committed fields
of §3.3 *without* the domain tag, in the same order, plus the signature:
`[subject_agent_id, epoch, head_sequence, head_hash, signed_at, signature(bytes, 64)]`.

To verify one entry: rebuild the §3.3 array (prepend the
`ai-memory/peer-head-attestation-v1` domain tag to the five committed
fields), encode it per §1, and check the 64-byte signature over those bytes
under `subject_pubkey`. The proof is genuine **equivocation** when both
entries verify, share the same subject + epoch + head_sequence, and commit
**different** head hashes — the subject signed two conflicting histories.
Everything needed is inside the record: no database, no network.

## 4. Multihash — the self-describing content digest

Write element `[6]` is a byte string of the form
`<codec varint> <length varint> <digest bytes>` (varints are unsigned
LEB128; both fit one byte for every current codec):

| Codec byte | Hash | Digest length |
|---|---|---|
| `0x12` | SHA2-256 | 32 (`0x20`) |
| `0x1e` | BLAKE3-256 | 32 (`0x20`) |

So `12 20 <32 bytes>` reads: "SHA2-256, 32 bytes, here they are." The codec
determines the length; a new hash algorithm gets a new codec byte, and old
records remain readable forever.

## 5. Keys and signatures

- **Public keys** are raw 32-byte Ed25519 verifying keys (RFC 8032), no
  wrapping, no DER/PEM.
- **Signatures** are raw 64-byte Ed25519 signatures, computed over the
  record's **entire canonical CBOR array bytes** (including the domain tag).
- Ed25519 signing is deterministic: the same key + bytes always yields the
  same 64 bytes.
- Verification advice: use a strict verifier (reject non-canonical /
  malleable encodings of the signature points), matching the reference
  implementation's `verify_strict`.

## 6. Worked example — decoding a real vector byte by byte

This is `vectors/signable_write_v2/a4_worked_example.hex` (the format spec's
Appendix A.4 record). Full hex, split at item boundaries:

```
8b                                            outer: array(11)
72 61692d6d656d6f72792f77726974652f7632      [0] text(18)  "ai-memory/write/v2"
71 686f73743a686f73742e6578616d706c65        [1] text(17)  "host:host.example"
66 676c6f62616c                              [2] text(6)   "global"
61 78                                        [3] text(1)   "x"
6b 6f62736572766174696f6e                    [4] text(11)  "observation"
74 323032362d30372d30395430303a30303a30305a  [5] text(20)  "2026-07-09T00:00:00Z"
58 22                                        [6] bytes(34) — multihash:
   12 20                                          SHA2-256, 32 bytes
   2cf24dba5fb0a30e26e83b2ac5b9e29e
   1b161e5c1fa7425e73043362938b9824               = SHA2-256("hello")
58 20 07070707…07 (32 × 0x07)                [7] bytes(32) instance_key_id (placeholder)
58 20 abababab…ab (32 × 0xab)                [8] bytes(32) model_version_ref (placeholder)
81 00                                        [9] array(1)[0] — session_id ABSENT
00                                           [10] uint(0) — suite_tag = Ed25519+SHA-256
```

Reading it head byte by head byte:

- `0x8b` = `0x80 | 11` → major 4 (array), 11 elements inline.
- `0x72` = `0x60 | 18` → major 3 (text), 18 bytes inline; the next 18 bytes
  are the ASCII of `ai-memory/write/v2`.
- `0x74` = `0x60 | 20` → text(20): the RFC 3339 timestamp.
- `0x58 0x22` → major 2 (bytes) with info 24 ("length in next 1 byte"),
  length `0x22` = 34: the multihash. Inside it, `0x12` says SHA2-256 and
  `0x20` says 32 digest bytes — and indeed those 32 bytes are exactly
  SHA2-256 of the 5 ASCII bytes `hello`. (Text lengths up to 23 fit inline;
  34 doesn't, hence the `0x58` one-byte-length form.)
- `0x81 0x00` → array(1) containing uint 0: the §1 presence wrapper saying
  session_id is ABSENT.
- The final `0x00` → uint 0: suite_tag.

Re-encode those decoded fields with the §1 rules and you reproduce the hex
above exactly — that is the whole conformance re-encode obligation. For the
signed variant of this record (`vectors/signed/write_v2_signed.hex`), the
64-byte signature in `manifest.json` verifies under the manifest's 32-byte
public key over exactly these re-encoded bytes.

## 7. What is deliberately NOT here

- **v1 records** (CBOR *maps* with sorted keys, the pre-v1.0 `Signable*`
  family) are a different, older encoding; a v1 record never verifies under
  a v2 domain tag. Their spec lives in the repository history — see the
  Portability v2 spec (`docs/spec/PORTABILITY-V2.md`) §V2-6 for how the two
  coexist in an export.
- **The export envelope** (the JSON document that carries memories, links,
  and these signed records between stores) is specified in
  `docs/spec/PORTABILITY-V2.md`; this file covers the signed *bytes* inside
  it.
- **Trust policy** (which keys to accept, epoch/revocation rules) is a
  verifier concern, spec §7 — this file only makes the bytes readable.
