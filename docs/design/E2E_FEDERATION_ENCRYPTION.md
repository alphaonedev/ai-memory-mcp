# End-to-end federation encryption (`0x05` scope envelope)

Status: #8278 slice E1 provides the envelope, the scope-key store with its
audit log, and escrow. #8278 slice E2 (sync path, capability gate,
`/keys/scope`, row mappers, embedding withholding) and the Codex lane (SAL
ledger, rotation cursor, CLI, doctor, CI guards) build on this contract.
Parent issue #8268.

Decision record: 3-agent vote (6def5ab6), recorded in ai-memory `b5713886`;
operator directive `b577ee87`. Decisions D1 to D5 below are binding; this
document fixes the details the vote left to the implementer. The review
rulings of PR #8279 rounds 2 and 3 (conductor god-f2) are recorded as decision
lines (R2-amended replaces the row-version part of R2):

* `decision: D1 stanzas live in the ledger: each scope-key record carries one id-bound stanza per reader KEK plus the escrow stanza; rows carry only the key id and epoch (3-agent vote (6def5ab6))`
* `decision: D2 the 0x05 inner layer is a new HKDF-salted layout (per-record DEK wrapped under HKDF(wrap_salt, scope key)), not a reuse of the 0x03 layout (3-agent vote (6def5ab6))`
* `decision: R1 namespace marker = ledger has an epoch; refusal enforcement in E2 (conductor god-f2, amends D2 scope, 3-agent vote (6def5ab6))`
* `decision: R2 AAD gains row version in E1; writer authenticity via record signing in E2 (conductor god-f2, amends D2 AAD field list, 3-agent vote (6def5ab6))`
* `decision: R3 audit entries in E1, signed operator-authorised changes at the E2 mTLS gate (conductor god-f2, D3 as voted)`
* `decision: R4 UnknownKey is pinned through both open funnels (open_content_scoped_in, open_content_bound) by named tests (conductor god-f2)`
* `decision: R5 no constant-initialised buffer reaches a key, nonce or salt; random inputs are built from CSPRNG draws and test bytes are derived (conductor god-f2)`
* `decision: R6 the security docs describe E1 as built; embedding withholding and the no-placeholder rule for every open site are E2 (conductor god-f2)`
* `decision: R7 stanzas live in the ledger, rows are not self-contained, every reader depends on /keys/scope (D3 choice (b)); the D4 partial-result signal is a typed error variant added in E1 (SealedForeign) and surfaced in E2 (conductor god-f2)`
* `decision: R8 escrow is tested on the real recovery path: the recovery private key alone opens a content row, a moved escrow stanza is refused StanzaBindingMismatch (conductor god-f2)`
* `decision: R9 the 0x05 layout is pinned by a known-answer vector computed independently of the crate (Appendix A) (conductor god-f2)`
* `decision: R10 the remaining review findings land in E1: per-field nonce and salt uniqueness, supersede recovery-key compare, no-follow descriptor-checked reads, plaintext zeroized on NotUtf8, non_exhaustive public error enums, Zeroizing stanza secret (conductor god-f2)`
* `decision: R11 ScopeKeyStore = sync Send+Sync cache contract with write-through and versioned fail-closed freshness, async ledger on MemoryStore in E2 (3-agent vote (6def5ab6), B over A)`
* `decision: R12 record validation returns the typed ScopeKeyStoreError, not a String error (QUAL-7 ceiling) (conductor god-f2)`
* `decision: R2-amended content AAD binds memory id, namespace, key id, epoch, format version and role only, not the row version, because version changes on non-content writes and on federation merge without re-sealing (lifecycle_write.rs:84, storage/mod.rs:18356, postgres.rs:25297); replay protection is E2 record signing (conductor god-f2, amends R2, no vote: single-correct-answer fix inside the voted D2 layout)`
* `decision: R13 audit entry binds key id and key check because the E2 signature must cover the key, not only the public inputs (security r2 M2)`
* `decision: R14 the audit hash chain and the stanza id prefix are pinned by named tests and mutation runs (an edited middle line is refused AuditChainMismatch; a stanza for another key id, epoch or namespace does not parse) (security r2 L1)`
* `decision: R15 the new count assertion is declared with a Count-Declared trailer and the duplicated unreadable-file detail is one named constant; the literal baseline is never bumped (security r2 L2, code r2 C3)`
* `decision: R16 one erasable-version SSOT for both backends over keeping 0x03 on Postgres because the signed erasure kind must not depend on the backend (code r2 C1, CLAUDE.md SAL rule)`
* `decision: R17 namespace marker re-reads the cold store on a cache miss over a caller-supplied freshness head because the E2 refusal that consumes it has no head to supply (code r2 C2, R11 fail-closed freshness)`
* `decision: R18 the placeholder open sites name their E2 change, the commit crash window and the count-only ledger head are stated as known E1 properties, and open_content_scoped is documented as test-only in E1 (code r2 I-a to I-d)`

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

Embeddings are derived from content, so they leak it. In #8278 slice E2 a
node withholds vectors of `0x05` rows from every peer that is not a reader
(D4); a reader re-embeds locally after it opens the row. E1 has no sync path,
so it sends no vectors anywhere.

Out of the model: a compromised reader node (it holds the key by design), and
traffic analysis of row sizes (the envelope is length-preserving plus a fixed
125-byte overhead).

### Integrity

The scope key is symmetric and every reader holds it. It gives
confidentiality and row binding, not writer authenticity: any reader of a
namespace can produce an envelope that opens, so any reader can forge a row
in that namespace (new content under a valid key, id and epoch). The AAD
does not bind the row version (R2-amended, section 3): an older envelope of
the same row still opens, so the envelope gives no replay protection, and a
reader writing a fresh envelope is not detected by the envelope. Writer
authenticity and replay protection are record signing (signed events, Ed25519
over the row including its content and version, verified against
`agent_pubkey_history`) in #8278 slice E2. Until then, write authority is the
existing federation write authorization, not the envelope.

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

The row version (`Memory::version`) is not an AAD input (R2-amended). The
version changes on writes that never touch content and never re-seal, so an
AAD over it would make the row unreadable after any of them. Every writer of
`version` was checked: `set_lifecycle_state` (storage/lifecycle_write.rs:84),
`operator_dequarantine` and `dequarantine` (storage/mod.rs:4133, :4195),
`stamp_contaminated_descendants_as` (storage/mod.rs:13690), `swarm_rewind`
(storage/mod.rs:13995), `reown` (storage/mod.rs:20151),
`observe_and_release_sqlite` (storage/decontaminate.rs:167),
`reclassify_memory_kind` (store/sqlite.rs:3927), and the federation merges
`INSERT_IF_NEWER_SQL` (storage/mod.rs:18356, `MAX(version)`) and
`apply_remote_memory` (store/postgres.rs:25297, `GREATEST(version)`). None of
them changes `memory_id`, `namespace` or the envelope, so no remaining AAD
input changes without a re-seal. Replay of an older envelope of the same row
is detected by E2 record signing, which binds content and version together.

### Opening

`open_content` (no row context) refuses a `0x05` envelope with the typed
`BindingRequired` error; it never guesses a binding. `open_content_bound`
takes the row's `memory_id` and `namespace` and dispatches `0x05` to the scope
path; every other version behaves exactly as `open_content`. E2 moves the
row mappers onto `open_content_bound`.

### Crypto-erase

`0x04` stays valid for `0x05` rows. The erasable version bytes are one
source of truth, `CRYPTO_ERASABLE_ENVELOPE_VERSIONS` (`0x03` and `0x05`, built
from `RECORD_ENVELOPE_VERSION` and `SCOPE_ENVELOPE_VERSION`), read by
`envelope_is_crypto_erasable` on SQLite and bound into the Postgres erase
predicates (single-row delete, forget, eviction) (R16). On both backends every
hard-delete funnel rewrites a `0x05` row to the marker before the `DELETE` and
signs the erasure kind `key-destroyed` (test
`tests/scope_envelope_erase_parity_8278.rs`). The DEK exists only inside
`wrapped_dek`; rewriting the
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
`load_by_key_id_fresh`, `namespace_is_e2e`, `ledger_head`, `audit_log`,
`refresh_from_ledger`, `add_recipient`, `remove_recipient`, `supersede`.

`ScopeKeyStore` is a synchronous `Send + Sync` cache contract (R11). Lookups
are pure memory behind an `RwLock`; no lookup touches the disk or awaits. The
files are the cold store: loaded once at construction
(`FileScopeKeyStore::open`), reloaded by `refresh_from_ledger`, and written
through by every mutator in the same call before it returns, so the mutating
process never answers from a cache older than its own writes. The cache
records each namespace's ledger head (its audit entry count).
`load_by_key_id_fresh` takes the head a peer advertised and refuses with the
typed `SealedForeign` error while the cache is older, until a refresh catches
up. `namespace_is_e2e` answers a cached namespace with an epoch from memory;
on a cache miss (or a cached namespace with no epoch) it takes the shared
`flock`, re-reads that namespace's records and audit log in the same call,
and caches the result (R17). A store opened before another process minted
epoch 1 therefore never reports the namespace as plaintext: the E2 refusal
that consumes the marker has no peer head to supply. A namespace whose files fail verification is cached as that refusal, so
its lookups fail closed while other namespaces keep working. The async ledger
methods on `MemoryStore` (load, append, refresh) for SQLite and Postgres are
#8278 slice E2 with the Codex SAL slice; they fill the same cache.

The file-backed store keeps records at
`<key_dir>/scope-keys/<slug>.scope.<epoch>.json` and the audit log at
`<key_dir>/scope-keys/<slug>.audit.jsonl`, both mode `0600` under the same
secure-directory checks as the agent keys; `slug` is the first 16 bytes of
`SHA-256(namespace)` in hex, so namespace text never reaches a file name.
Mutations hold an exclusive `flock` on `scope-keys/.scope-keys.lock`, loads
hold it shared; the lock order is always `flock` first, cache `RwLock`
second. Record writes stage to a sibling file and rename. Every read checks
the directory chain, opens the file without following a link
(`O_NOFOLLOW`), and checks the open descriptor (`fstat`: a regular file,
owner-only mode) before reading from that same descriptor. A record with
group/other access, a link in its place, a missing epoch, malformed JSON or
a stored key id that differs from the one an envelope names is refused
`RecordCorrupt` / `KeyIdMismatch`.

### Audit log (R3)

Every mutation appends one entry to the namespace's audit log: `mint`,
`add_recipient`, `remove_recipient`, `supersede`. An entry records who (the
process agent id), what (the action and the KEK fingerprint added or
removed), the epoch touched, the previous epoch and the new epoch, the
key id and `key_check` of that epoch (R13), the sorted reader fingerprints of
that epoch after the change, the escrow recovery fingerprint, an RFC 3339
timestamp, and the SHA-256 of the previous entry's line. The log is append-only and hash-chained: `seq` is dense from 1,
and an entry whose previous-epoch pointer is not the head's epoch is refused
`AuditChainMismatch` before anything is written. A load replays the chain and
cross-checks it with the records (epoch count, each epoch's key id and
`key_check`, readers and escrow fingerprint): a record edited outside the
store, a whole record substituted from public inputs (a fresh key wrapped to
the same readers and escrow key), an edited middle line, a removed or
reordered entry, or a torn last line refuses the namespace. An entry naming a
different key id or `key_check` for an epoch the log already holds is
refused before it is written.

Authority in E1 is the process boundary: the owner-only `0700` key-directory
chain and local writers only. Signed, operator-authorised reader-set changes
are enforced at the E2 mTLS `/keys/scope` gate (D3); the audit entry format is
what that gate signs.

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
* `supersede` refuses with `RecoveryKeyChanged` when the enrolled recovery
  key is not the one the current epoch is escrowed to: the escrow chain never
  forks silently (re-escrow is the explicit recovery-key rotation, #3717).
* `supersede` writes epoch N+1 FIRST, then closes epoch N's window, then
  appends the audit entry. A crash before the entry lands leaves records the
  log does not account for; the next load refuses the namespace
  (`AuditChainMismatch` / `RecordCorrupt`) instead of guessing, and the
  doctor (Codex lane) reports it for repair. Known E1 property (code r2 I-a):
  every mutator writes records before its audit line, so a crash in that
  window refuses every epoch of the namespace until the doctor repair, which
  is the E2 / Codex-lane resolution.
* Known E1 property (code r2 I-b): the ledger head is an entry count, so two
  forked ledgers with equal counts compare equal in `load_by_key_id_fresh`.
  The E2 record and audit-entry signatures bind content (now including each
  epoch's key id and `key_check`), which is what tells such forks apart.
* Known E1 property (code r3 I-r3a, security r3 INFO b): `namespace_is_e2e`
  caches only a namespace with an epoch. A miss (every plaintext namespace,
  every call) takes the shared `flock` and rescans the key directory, with no
  negative cache; a key directory that cannot be read answers end-to-end.
  Size that cost before E2 calls the marker on async request paths.
* Known E1 property (code r3 I-r3b): the Postgres crypto-erase parity test
  stops at the first failing delete funnel, so a red run names one funnel; a
  per-funnel collect-then-assert would name every regressed funnel at once.
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
* A namespace is end-to-end exactly when its scope-key ledger holds at least
  one epoch (`ScopeKeyStore::namespace_is_e2e`, R1); a ledger that cannot be
  read counts as end-to-end (fail closed). For an E2E namespace the sender
  never emits, and the receiver never accepts, a non-`0x05` representation of
  a row (plaintext, `0x02`, `0x03`). E1 provides the marker; the refusal is
  enforced in #8278 slice E2.
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

Rows are not self-contained: the stanzas live in the ledger (D1), so every
reader depends on its ledger and on `/keys/scope` to obtain a key (D3 choice
(b)). A node whose ledger is older than the head a peer advertised gets the
typed `SealedForeign` error from `load_by_key_id_fresh` (R7), never "not a
reader" and never an empty result. E1 adds the variant; E2 surfaces it as the
D4 partial-result signal on read and sync paths.

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
| record file insecure, malformed, gapped, or a link | `RecordCorrupt` |
| audit log broken, or records disagree with it | `AuditChainMismatch` |
| enrolled recovery key differs from the current escrow at supersede | `RecoveryKeyChanged`, nothing written |
| local ledger older than the head a peer advertised | `SealedForeign` |
| peer without capability bit | sender refuses the push (E2) |

In E1 the scope open functions (`open_scoped`, `open_content_scoped_in`,
`open_content_scoped`, `open_content_bound`) never return plaintext, an empty
string or a placeholder for a row they could not open: each refusal is one of
the typed errors above. Two open sites outside the envelope code fall back to
the raw column when `open_content` refuses
(`open_content(..).unwrap_or(raw_content)`): `restored_cid_stamp`
(`src/storage/mod.rs`, SQLite) and `archive_restore_inner`
(`src/store/postgres/federation_by_id_4447.rs`, Postgres). They hash or
restore the column bytes, not content shown to a caller, and #8278 slice E2
changes both to the bound open with a typed refusal, so the no-placeholder
rule then holds for every open site.

## 10. Decisions and remaining questions

1. **Signing records and `/keys/scope` responses.** Decided (R3): `0x02` ECIES
   does not authenticate the sender, so in E1 a party able to write a stanza
   is bounded by the process boundary (owner-only key-directory chain, local
   writers) and every change is in the hash-chained audit log. In E2 the
   minting node signs each record (Ed25519, canonical JSON without
   `recipients`) and the audit entries, `/keys/scope` responses are signed,
   readers verify against `agent_pubkey_history`, and the record `format`
   moves to 2.
2. **Who may mint for a namespace.** Recommended: the namespace owner node
   only (the governance owner); other nodes request the key.
3. **Reader-set authority.** Decided (R3): E1 authority is the process
   boundary and the audit log records every reader-set change; operator
   authorisation and signing of reader-set changes are enforced at the E2
   mTLS `/keys/scope` gate (D3), with the namespace governance standard as
   the source and the ledger mirroring it.
4. **Escrow key rotation.** Recommended: a new recovery key re-escrows every
   current epoch through the rotation cursor; old escrow stanzas stay until it
   completes.
5. **Plaintext metadata.** Recommended: keep title/tags/metadata plaintext in
   v1.0.0 (search and listing depend on it) and document it; sealed metadata
   is a later format.
6. **Key-file protection at rest.** Records hold only wrapped keys (stanzas
   need a KEK secret), so mode `0600` plus the directory checks match the
   agent key files. Recommended: no extra passphrase layer.

## Appendix A. Known-answer vector (R9)

Test `scope_envelope_known_answer_vector_8278` (`src/encryption/scope/tests.rs`)
pins the exact bytes. Each input is the first N bytes of
`SHA-256("kat-8278/" || label)`; the expected values were computed
independently of the crate (Python `cryptography`: HKDF-SHA256 and
ChaCha20-Poly1305).

| Input | Label / value |
|---|---|
| scope key (32) | `scope-key` |
| key id (16) | `key-id` |
| DEK (32) | `dek` |
| wrap salt (16) | `salt` |
| wrap nonce (12) | `wrap-nonce` |
| inner nonce (12) | `inner-nonce` |
| epoch | 3 |
| memory id | `mem-kat` |
| namespace | `test/kat-8278` |
| content | `known answer #8278` |

```text
wrap AAD    01054c47463e6b7ed21881e2861ff46b04b600000003000000076d656d2d
            6b61740000000d746573742f6b61742d38323738
content AAD 02054c47463e6b7ed21881e2861ff46b04b600000003000000076d656d2d
            6b61740000000d746573742f6b61742d38323738
HKDF okm    4646030666175724ba4a7341744114dc6544487cf9663060a7c7994b2023d413
envelope    054c47463e6b7ed21881e2861ff46b04b600000003e0cb9169fff94df3a7d3
            0c3f8ef1f53cad28efb547f47f4211997cf553b646cc498d4dac5e94d2d113
            3c16fd19402f9c614c349f6a8bdc13497d2d2545377d8aee8d360bbd58986b
            8f87b8083ffce1c4627aa7919b7ae3550813d939d3080695a77d03335b5dcb
            c6a0fd9f5adbaf43301ae3a53c0f438d153027
```

Round 3 (R2-amended) removed the row version from both AADs; the HKDF okm is
unchanged, the wrapped DEK and the inner ciphertext tags changed. The same
independent computation reproduces the round-2 vector byte for byte from the
old AAD before producing this one.

The two AADs differ only in the role byte. The test also checks that the
stored wrapped DEK and inner ciphertext do not verify under the other role
byte, and that sealing under it gives different bytes.
