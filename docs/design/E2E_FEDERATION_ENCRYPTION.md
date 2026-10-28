# End-to-end federation encryption (`0x05` scope envelope)

Status: E1 (envelope + scope-key store + escrow) landing in #8278. E2 (sync
path, capability gate, `/keys/scope`) and the Codex lane (SAL ledger, rotation
cursor, CLI, doctor, CI guards) build on this contract. Parent issue #8268.

Decision record: 3-agent vote (6def5ab6), recorded in ai-memory `b5713886`;
operator directive `b577ee87`. Decisions D1 to D5 below are binding; this
document fixes the details the vote left to the implementer and lists the open
questions with a recommended answer each.

## 1. Why

The at-rest schemes seal content to ONE node's X25519 key (`0x02` ECIES,
`0x03` per-record DEK). Federation therefore decrypts on the sender and
re-seals on the receiver, so the transport (behind TLS), every relay and every
peer's storage see plaintext. A `0x05` row is sealed under a key shared by the
namespace's reader set: the same bytes travel peer to peer and only a reader
opens them.

## 2. Threat model

Content of a `0x05` row is hidden from:

| Party | Holds | Why it cannot read |
|---|---|---|
| Transport / TLS terminator | the sync body | the body carries the sealed envelope, never plaintext |
| Storage of any node (disk, backup, DB dump) | the column bytes | needs the scope key; stanzas need a reader KEK secret |
| A peer outside the reader set (including relays) | the envelope, the record metadata | no recipient stanza for its KEK; `/keys/scope` refuses it |
| A revoked reader | old epochs' keys it already pulled | new rows use the next epoch, which it never receives; old rows are covered by D5 re-encrypt |

Stays plaintext by design (needed for routing, filtering and listing without a
key): `title`, `tags`, `metadata`, `namespace`, timestamps, ids. Operators must
not put secrets there; the docs say so (docs/SECURITY.md, Data at rest).

Embeddings are derived from content, so they leak it. A node withholds vectors
of `0x05` rows from every peer that is not a reader (D4); a reader re-embeds
locally after it opens the row.

Out of the model: a compromised reader node (it holds the key by design), and
traffic analysis of row sizes (the envelope is length-preserving plus a fixed
125-byte overhead).

## 3. Envelope `0x05` byte layout

Same column as `0x02`/`0x03`/`0x04` (D2). Fixed 109-byte header, then the
inner ciphertext:

```text
offset  len  field
0       1    version      = 0x05
1       16   key_id       random id minted with the scope key
17      4    epoch        u32 big-endian, 1-based scope-key generation
21      16   wrap_salt    random per record
37      12   wrap_nonce   ChaCha20-Poly1305 nonce of the DEK wrap
49      48   wrapped_dek  32-byte per-record DEK + 16-byte tag
97      12   inner_nonce  ChaCha20-Poly1305 nonce of the content
109     >=16 inner_ct     content ciphertext + tag under the DEK
```

Minimum length 125 bytes (empty content). Shorter input is refused
`Truncated`; any other leading byte is refused by the version dispatcher as an
unknown envelope version (fail closed, unchanged).

Keys:

* DEK: 32 random bytes per record, zeroized after use.
* DEK-wrap key: `HKDF-SHA256(salt = wrap_salt, ikm = scope_key, info =
  "ai-memory/v1.0.0/e2e-scope/dek-wrap-key/v5" || key_id || epoch_be)`. It is
  unique per record, so random 96-bit nonces never repeat under one key.

### AAD (both AEAD operations)

```text
role(1) || 0x05 || key_id(16) || epoch_be(4)
        || len32_be(memory_id) || memory_id
        || len32_be(namespace) || namespace
```

`role` is `0x01` for the DEK wrap and `0x02` for the content, so the two
ciphertexts cannot stand in for each other. Lengths are 32-bit big-endian
prefixes so bytes cannot move between `memory_id` and `namespace`. The
namespace is NOT stored in the header: the row's own `namespace` column is the
binding input, so a row moved to another namespace, a ciphertext copied
between rows, or an edited key id / epoch all fail authentication.

### Opening

`open_content` (no row context) refuses a `0x05` envelope with the typed
`BindingRequired` error; it never guesses a binding. `open_content_bound`
takes the row's `memory_id` and `namespace` and dispatches `0x05` to the scope
path; every other version behaves exactly as `open_content`. E2 moves the
row mappers onto `open_content_bound`.

### Crypto-erase

`0x04` stays valid for `0x05` rows: `envelope_is_crypto_erasable` is true for
`0x03` and `0x05`. The DEK exists only inside `wrapped_dek`; rewriting the
column to the `0x04` marker destroys it, and holding the scope key no longer
recovers that record. Peer copies are erased where the erase is applied; E2
propagates the erase over sync (a `0x04` envelope replaces the peer's copy).

## 4. Scope keys

### `ScopeKey`

32 random bytes plus its identity (`namespace`, `key_id`, `epoch`). The secret
zeroizes on drop and is redacted from `Debug`.

### `ScopeKeyRecord` (one per namespace per epoch)

```json
{
  "format": 1,
  "namespace": "team/alpha",
  "epoch": 1,
  "key_id": "<32 hex>",
  "key_check": "<32 hex>",
  "created_at": "<RFC 3339>",
  "superseded_at": null,
  "recipients": [
    {"agent_id": "node-a", "kek_fingerprint": "<hex>", "wrapped": "<base64url 0x02 envelope>"}
  ],
  "escrow": {"recovery_fingerprint": "<hex>", "wrapped": "<base64url 0x02 envelope>"}
}
```

* Each stanza is `encrypt_bytes` (the `0x02` ECIES path) of an id-bound
  plaintext: `0x05 || key_id || epoch_be || len16_be(namespace) || namespace ||
  secret(32)`. Unwrapping refuses a stanza whose embedded identity differs
  from the record (`StanzaBindingMismatch`), so a stanza copied from another
  namespace or epoch is useless.
* `key_check` = `HKDF-SHA256(ikm = secret, info =
  "ai-memory/v1.0.0/e2e-scope/key-check/v5" || key_id || epoch_be ||
  namespace)`, first 16 bytes. Verified in constant time on every unwrap and
  before a new recipient is added, so a wrong secret never enters the ledger.
* `created_at` / `superseded_at` form half-open validity windows; supersede
  sets the old record's `superseded_at` to the new record's `created_at`.
* Unknown JSON fields are refused (`deny_unknown_fields`), and `format` must
  be 1.

### Ledger (`ScopeKeyStore` trait)

Modelled on `agent_pubkey_history`: append-only per namespace, epochs dense
from 1, never deleted. Operations: `mint` (idempotent: returns the existing
current key), `history`, `load_epoch`, `load_current`, `load_by_key_id`,
`add_recipient`, `remove_recipient`, `supersede`.

The file-backed store (E1) keeps records at
`<key_dir>/scope-keys/<slug>.scope.<epoch>.json` with mode `0600` under the
same secure-directory checks as the agent keys; `slug` is the first 16 bytes
of `SHA-256(namespace)` in hex, so namespace text never reaches a file name.
Mutations hold an exclusive lock on `scope-keys/.scope-keys.lock`; writes
stage to a sibling file and rename. A record with group/other access, a
missing epoch, malformed JSON or a stored key id that differs from the one an
envelope names is refused `RecordCorrupt` / `KeyIdMismatch`.

The SAL DB ledger (SQLite and Postgres) implements the same trait; that is the
Codex lane.

### Escrow

Every scope key is wrapped under the deployment recovery public key
(`<key_dir>/recovery.x25519.pub`, the #3717 escrow key) at mint, with the same
id-bound plaintext. `mint` and `supersede` refuse with `EscrowUnavailable`
when no recovery key is enrolled: a scope key that no recovery path can open
is a data-loss trap, so the store fails closed. Recovery
(`ScopeKeyRecord::recover_with`) checks the recovery fingerprint, unwraps,
checks the embedded identity and `key_check`; any mismatch is refused.

`keys recover` extension (Codex lane, documented here): `ai-memory keys
recover --scope <namespace> [--epoch N] --recovery-key <file> --grant
<agent-id>` loads the record(s), recovers each epoch's key with the private
recovery key and re-grants it to the named node's current KEK via
`add_recipient`. The library half (`recover_with` + `add_recipient`) lands in
E1; the CLI surface (verb, SSOT pins, doctor) lands with the Codex lane.

### Epoch semantics

* Epoch 1 is minted on first write into an E2E namespace.
* `supersede` writes epoch N+1 FIRST, then closes epoch N's window. A crash in
  between leaves two open-ended records; the highest epoch is current, so
  there is never a moment without a current key.
* New rows always seal under the current epoch. Old rows keep naming their
  epoch and open with that epoch's key until rotation rewrites them.
* Removing a recipient (`remove_recipient`) stops the ledger handing that key
  out; it does not revoke what the node already holds. Revocation is
  `supersede` with the reduced reader set plus a D5 rotation of old rows.
* The last recipient of an epoch cannot be removed (`LastRecipient`).
* Epochs are federation-wide (D5): every node agrees on epoch N of a
  namespace by key id; a divergent key id for the same epoch is detected
  (`KeyIdMismatch`) and refused, never merged.

## 5. Capability-bit contract (E2 implements)

* Peers advertise an `e2e_envelope_v1` capability bit in the federation
  handshake.
* Sync bodies gain a nullable `envelope` field (base64url of the column
  bytes). A `0x05` row travels with `content` empty and `envelope` set.
* The sender hard-rejects pushing a `0x05` row to a peer without the bit (it
  never falls back to sending plaintext).
* The receiver rejects a row with neither `content` nor `envelope`, and a row
  with both.
* A receiver that is not a reader stores the row verbatim as **sealed-foreign**
  (section 8) and relays forward it unchanged (D4).

## 6. `/keys/scope` contract (E2 implements, D3)

`POST /keys/scope` over the federation mTLS listener.

Request:

```json
{"namespace": "team/alpha", "epoch": 3, "key_id": "<32 hex>", "kek_public": "<base64url X25519>"}
```

`epoch` and `key_id` are optional (absent = current). Authorization, all of:

1. The mTLS client certificate maps to an Ed25519 node identity and the
   request is signed by it (the existing federation request signature).
2. That identity is in the namespace's reader set for the requested epoch.
3. `kek_public` is the X25519 KEK bound to that identity's credential (the
   ledger's `kek_fingerprint` for it); a request naming any other KEK is
   refused.

Response (`200`):

```json
{"record": { "...ScopeKeyRecord with only the requester's stanza..." }}
```

The server never returns the raw secret, other readers' stanzas or the escrow
stanza. Refusals: `403` not a reader, `404` unknown namespace/epoch, `409` key
id mismatch, `400` malformed. Every refusal is logged with the typed class and
no key material.

## 7. Rotation modes (D5)

One resumable cursor per (namespace, target epoch), persisted in the ledger:

* **rewrap** (default): for each `0x05` row of the old epoch, open the
  wrapped DEK with the old scope key and re-wrap it under the new key and
  epoch (new salt, new nonce, new AAD). The inner ciphertext is untouched.
  Cheap; does not protect against a revoked reader who saved old DEKs.
* **re-encrypt** (opt-in): open the row fully and seal it fresh under the new
  epoch (new DEK). Use after a revocation for cause.

Both modes: verify-then-swap (the new envelope is opened and compared with the
plaintext before the column is replaced, in one transaction per batch), the
cursor commits with the batch, a crash resumes from the cursor, and the old
key is kept until the cursor reports completion. The old record is never
deleted (it stays in the ledger as superseded).

## 8. Sealed-foreign rows

A node that receives a `0x05` row but holds no stanza for it stores the
envelope verbatim with state `sealed_foreign`: it is listed (plaintext
metadata), never embedded, never searched by content, never decrypted, and
forwarded unchanged. If the node later becomes a reader it opens the row in
place; nothing is re-fetched.

## 9. Failure semantics (all fail closed)

| Condition | Result |
|---|---|
| unknown envelope version | refused, typed unknown-version error |
| `0x05` without row binding | `BindingRequired` |
| truncated envelope | `Truncated` |
| no current key / unknown key id | `UnknownKey` |
| node not a reader | `NotAReader` |
| stanza or escrow identity mismatch | `StanzaBindingMismatch` / `RecoveryKeyMismatch` |
| AEAD failure (tamper, wrong row, wrong key) | `Authentication` |
| no recovery key at mint | `EscrowUnavailable`, nothing written |
| record file insecure, malformed, gapped | `RecordCorrupt` |
| peer without capability bit | sender refuses the push (E2) |

No path returns plaintext, an empty string or a placeholder for a row it could
not open.

## 10. Open questions (each with the recommended answer)

1. **Signing records and `/keys/scope` responses.** `0x02` ECIES does not
   authenticate the sender, so a party able to write a stanza could substitute
   a key it knows. Recommended: the minting node signs each record (Ed25519,
   canonical JSON without `recipients`) and `/keys/scope` responses; readers
   verify against `agent_pubkey_history`. E2 adds the signature field; the
   record `format` moves to 2.
2. **Who may mint for a namespace.** Recommended: the namespace owner node
   only (the governance owner); other nodes request the key.
3. **Reader-set authority.** Recommended: the namespace governance standard
   (E2), not the key file; the ledger mirrors it.
4. **Escrow key rotation.** Recommended: a new recovery key re-escrows every
   current epoch through the rotation cursor; old escrow stanzas stay until it
   completes.
5. **Plaintext metadata.** Recommended: keep title/tags/metadata plaintext in
   v1.0.0 (search and listing depend on it) and document it; sealed metadata
   is a later format.
6. **Key-file protection at rest.** Records hold only wrapped keys (stanzas
   need a KEK secret), so mode `0600` plus the directory checks match the
   agent key files. Recommended: no extra passphrase layer.
