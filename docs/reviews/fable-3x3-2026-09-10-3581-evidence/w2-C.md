## Ballot W2-C (adversary: apply unsafe)
**Vote:** B — D fails on federation (inbound apply *is* signed and enrollment-gated by default) and is already absorbed on restore (#3199 is tag-track); four default-posture gaps wave 1 missed survive and must be written into #3581.

**Verified evidence (file:line):**
- Peer *key enrollment* is default-REQUIRED: `require_peer_enrollment_enabled()` returns `true` on unset (`src/handlers/federation_signing_check.rs:2508-2513`); the `(None,None)` arm refuses `peer_not_enrolled` (`:2458-2486`). Per-message sig + nonce default-on (`src/federation/signing.rs:240-249`). W1-A's "enrollment is opt-in" conflates this with the *authorship/namespace allowlist* (`AI_MEMORY_FED_PEER_ATTESTATION`), which is zero-config faith-based (`src/federation/peer_attestation.rs:143-144`). Different gates; both true.
- `asi-hard` cannot pin the allowlist gate: `inbound_write_namespace_authorized` returns `true` on `!attest_cfg.has_allowlist()` *before* reading `require_push_namespace_scope` (`src/federation/receive_auth.rs:1226-1228`), so the pinned `AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE=1` (`src/security_profile.rs:51`) is inert without the JSON allowlist; `security_profile.rs` never references `PEER_ATTESTATION_ENV`. Only `doctor --posture enterprise-federation` checks it (`src/enterprise_federation_posture.rs:453-498`); that boot gate is opt-in (`:780-784`).
- Even in zero-config an enrolled peer may author only as itself (`attest_sender`, `peer_attestation.rs:394-420`); third-party claims need a verified write-signature by default (`receive_auth.rs:505-525`). Self-authored relays land `attest_level=claimed`, accept-and-flag (`src/handlers/federation_receive.rs:914-931`); quarantine is opt-in (`receive_auth.rs:642-646`).
- Governance default is **Advisory** — "Log a warning and allow" (`src/config.rs:6128-6142`); `Enforce` is pinned only under `asi-hard` (`security_profile.rs:59`). Every `Permissions::evaluate` site is non-blocking on a default install.
- Restore: mtime newest-wins (`src/cli/backup.rs:857-880`), sha256-only manifest inside `if !args.skip_verify` (`:899-960`), no signature. SQLite-only: `resolve_sqlite_source` (`:452-466`) hits the pg refusal; standard L310 says so. Neither posture module mentions backup/restore (zero hits).
- HTTP direct writes require attestation when env unset (`src/identity/attest.rs:181-186`); keyless bind is loopback-only (`src/daemon_runtime.rs:5855-5883`); bulk shares the gate (`src/handlers/bulk.rs:885-887`). Import: `trust_source=false` restamps authorship, forged write-signatures are skipped (`src/portability/import.rs:88-116,223-237`); spine re-verified in-tx.
- GA envelope: "production-supported inside the published envelope, NOT CERTIFIED" (cert standard L278-283, L348-352).

**Where the assessment is wrong or overstated:**
- "Federation receive is fail-closed" is true for *identity* (enrollment, sig, nonce, forged-sig refusal) but not for *authorization*: namespace scope is faith-based until the allowlist is set, and the hardened posture cannot force it.
- The authorization row omits that the K3/K9 gate is Advisory by default; the 20 real `evaluate` sites deny nothing on a Standard install. #3549's resolver inherits this unless the #3125 ruling flips enforce for governed namespaces.
- Restore row should say "SQLite backend only; pg DR is outside the product" — that narrows, not removes, #3199.

**Where the assessment is right:**
- Restore is the one apply path with no signature and no posture pin; it is correctly a tag-track blocker (row 15 N12).
- No dispatch-level resolver; extraction during the freeze adds no control.
- Federation apply is signed at the transport and enrollment layers by default; D's "unsafe until apply is signed" is false there.

**Required amendments to #3581 before acceptance:**
1. Add to `asi-hard` KNOBS (or refuse boot): `AI_MEMORY_FED_PEER_ATTESTATION` must be present when any federation peer is configured, so the namespace-scope pin is not vacuous (`receive_auth.rs:1226`).
2. Record the Advisory default in the authorization row; #3549's #3125 ruling must state the Standard-posture default explicitly in README/`/capabilities`.
3. Restore row: scope to SQLite; #3199 must also cover `--skip-verify` under `asi-hard` (refuse) and add a `doctor --posture` check for signed-manifest capability.
4. Replace "peer enrollment default-on" with "key enrollment default-on; authorship/namespace allowlist opt-in"; drop W1-A's amendment 3 as stated.
5. Envelope NOT-CERTIFIED list must name: unsigned restore, Advisory governance, faith-based namespace scope, quarantine off.

**SIZE-FACTS:** D implies *more* code (signing on restore, a resolver, posture checks), not less. The eight authority/apply files total 22,844 lines; `src/` carries 204 distinct `AI_MEMORY_*` env literals, 34 of them require/allow/trust hatches. Reduction comes from collapsing hatches into one posture and moving in-file tests out, not from crate extraction, which relocates.

**One risk if followed / one risk if ignored:**
Followed: `asi-hard` is sold as the hardened posture while a pinned knob is inert and restore has no pin at all — false assurance to the exact buyer the envelope names.
Ignored: a default install replicates namespaces on faith, logs-but-allows every governance deny, and restores whatever file is newest.
