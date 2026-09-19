# ai-memory certification — Ballot procedure (§4 and §5 of the Mission-Critical Certification Standard, operationalised)

<!-- #3557 (N22, item 18): the review-wave and issuance rules of the adopted standard
(docs/compliance/MISSION-CRITICAL-CERTIFICATION-STANDARD-v1.md, §4 and §5) written as
the step-by-step procedure a wave follows. The rules are reproduced verbatim below; the
procedure adds only the order of operations and the record shapes. -->

## The rules (verbatim from the standard)

## 4. Review waves and independence

Three waves × seven distinct reviewers per major qualification, 21 recorded ballots:
W1 independent findings; W2 adversarial counterexamples against W1; W3 final artifact
adjudication. Distinct means distinct principals (a person or an organisation) recorded
as `reviewer_identity`; sessions of one model family within one organisation count once.
Every ballot and every rejected claim is preserved in the bundle
(`docs/reviews/gpt6-astra-20260905-evidence/` is the precedent). A wave with fewer than
seven ballots blocks issuance. Smaller 3×3 waves are permitted for intermediate
documents and are labelled as such (this standard and its companion audit were reviewed
3×3 by one principal, and therefore carry the VENDOR SELF-CERTIFIED label below).

At least one wave-3 ballot must come from a reviewer independent of the vendor and of the
model family that authored the artifact; otherwise the certificate carries the label
**VENDOR SELF-CERTIFIED**.

## 5. Issuance, expiry, re-issue, disconfirmation

One immutable bundle per artifact. The certificate expires on any change to the watched
surface set: `src/federation/**`, `src/handlers/federation_receive.rs`,
`src/handlers/federation_signing_check.rs`, the `AI_MEMORY_FED_*` name set, and, added by
this standard, `src/identity/**`, `src/storage/migrations.rs`, the write funnels in
`src/store/postgres.rs`, and `src/handlers/admin.rs`. The enforcer is the widened
`check-cert-expiry.sh` (N30). Historical certificates are retained with expiry banners
and never edited to look current. A passing older source SHA never certifies new
identity, migration or federation code.

Preconditions of issuance: the deployed node's `ai-memory doctor --posture` output is
attached and shows the certified posture (including `synchronous=FULL` for SQLite);
audit-spine retention declared (days) and exportable to an external log store; every
certified node NTP-disciplined to UTC with `clock_source` in the run record; a
documented key-management procedure (generation, rotation, compromise, revocation) for
agent keys, daemon keys and at-rest keys.

Disconfirmation clauses (any one voids the certificate): the four existing §7 clauses of
`docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md`; any `PASS` row with
`oracle_kind: self-report`; any published number not recomputable from a linked
immutable artifact; any dashboard observation whose freshness timestamp postdates its
source artifact's `finished_at_utc`.



## The procedure

### Before wave 1
1. **Pre-register the envelope.** `docs/compliance/v1.0.0-DECLARATION.md` is committed
   and its SHA-256 pinned in `scripts/qc-allowlists/declaration.sha256`
   (`scripts/check-declaration-hash.sh` is a required context). Every run record written
   from here on carries that hash as `envelope_ref`; a differing hash is `FAIL` (§0.2).
2. **Name the artifact.** One immutable bundle per artifact (§5): source commit, binary
   SHA-256, the `doctor --posture` output showing the certified posture, the
   `clock_source` of every certified node, the audit-spine retention (days) and the
   key-management procedure — the §5 preconditions — are attached before any ballot.
3. **Seat the reviewers.** Seven distinct principals per wave, recorded as
   `reviewer_identity` (a person or an organisation; sessions of one model family within
   one organisation count once). Record, for the wave-3 seats, which reviewer is
   independent of the vendor AND of the model family that authored the artifact; if none
   is, the certificate will carry **VENDOR SELF-CERTIFIED** and the procedure continues.

### Wave 1 — independent findings
4. Each reviewer files findings against the §1 evidence schema without sight of the other
   six. A finding names the gate (G1–G8), the evidence artifact, and the disposition it
   argues for.

### Wave 2 — adversarial counterexamples
5. Each reviewer attacks wave-1 findings: a counterexample is a concrete input, run or
   artifact that would make a wave-1 `PASS` a `FAIL` (or the reverse). Rejected claims
   are preserved with their rejection, never deleted.

### Wave 3 — final artifact adjudication
6. Each reviewer casts one ballot per gate on the final artifact: `PASS`, `FAIL` or
   `ABSTAIN` with the evidence id. A wave with fewer than seven ballots blocks issuance.
7. Disconfirmation check before tallying (§5): any `PASS` row with
   `oracle_kind: self-report`, any published number not recomputable from a linked
   immutable artifact, or any dashboard observation fresher than its source artifact's
   `finished_at_utc` voids the certificate regardless of the tally.

### Issuance
8. Tally: a gate is green only when no wave-3 ballot is `FAIL` and the §0.2 declared
   targets are met by the pooled measurements bound to the pinned hash. G1–G8 all green
   → issue; otherwise the artifact is NOT CERTIFIED and the ballots are published as-is.
9. Label the certificate **VENDOR SELF-CERTIFIED** unless step 3 seated at least one
   independent wave-3 reviewer. Smaller 3×3 waves are permitted only for intermediate
   documents and are labelled as such.
10. Publish the bundle with all 21 ballots and every rejected claim
    (`docs/reviews/gpt6-astra-20260905-evidence/` is the precedent for the layout).

### After issuance
11. The certificate expires on any change to the watched surface set (§5); historical
    certificates keep their expiry banner and are never edited to look current.
12. A missed §0.2 target is published as a miss. The declaration is never softened; a new
    revision of `v1.0.0-DECLARATION.md` requires a `revision:` bump and a dated
    `revised after miss (YYYY-MM-DD): <reason>` line, and the pinned hash moves with it —
    the gate refuses any other edit.
