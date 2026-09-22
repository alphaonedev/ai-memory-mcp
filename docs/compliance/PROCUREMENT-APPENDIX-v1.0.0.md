# ai-memory v1.0.0 — Procurement appendix (§8 of the Mission-Critical Certification Standard)

<!-- #3557 (N22, item 18 of the standard's §6): the §8 table of the adopted standard
(docs/compliance/MISSION-CRITICAL-CERTIFICATION-STANDARD-v1.md) reproduced verbatim as
the stand-alone artifact a public-sector reviewer receives, with the certificate-half
framing. The table's rows are edited ONLY in the standard; this file is regenerated from
it. -->

> **Label: VENDOR SELF-CERTIFIED (3×3)** — see §4 of the standard and
> `docs/compliance/BALLOT-PROCEDURE.md`. **None of the areas below is certified today**;
> each row says where its evidence lands. The declared targets a reviewer measures a
> deployment against are in `docs/compliance/v1.0.0-DECLARATION.md` (SHA-256 pinned in
> `scripts/qc-allowlists/declaration.sha256`); the envelope and the NOT-CERTIFIED list are
> §0.1 of the standard; a buyer's reliance conditions are §7.

## §8 — What a public-sector reviewer will ask for

None of it is certified today.

| Area | Status | Where it lands |
|---|---|---|
| Control mapping (NIST SP 800-53 Rev 5 / 800-171; FedRAMP Moderate, StateRAMP, TX-RAMP baselines) | not written | appendix mapping G1–G8 to AC-3/AC-6, AU-2/AU-8/AU-9/AU-11, IA-2/IA-5, SC-8/SC-12/SC-13/SC-28, SI-7, CP-9/CP-10, CM-6/CM-14, IR-4/IR-6, RA-5, SA-11, SR-3/SR-4/SR-11 |
| Cryptographic module validation (FIPS 140-3) | not validated; NOT CERTIFIED | scope an `aws-lc-fips`-class build or state the exclusion |
| Audit-log retention, tamper evidence, SIEM export, clock source (AU-8) | spine exists (G7); retention and export undeclared | §5 preconditions |
| Data residency / region pinning for `hive(K)` | envelope axis in §0.1 | per-certificate declaration |
| Incident response, vulnerability disclosure SLA, CVE/KEV cadence, breach notification | rehearsal only (item 22b) | policy document alongside the certificate |
| Supply chain: SBOM exists (CycloneDX, `release.yml:435`); SLSA provenance level, VEX, CISA Secure Software Development Attestation (OMB M-22-18 / M-23-16) | not stated | G6 evidence bundle |
| Assessor independence (3PAO-style) | all waves one principal | §4 VENDOR SELF-CERTIFIED until met |
| Data classification, PII/PHI handling, records retention, right-to-erasure boundary | NOT CERTIFIED beyond the erasure line | envelope declaration |
| Key management (KMS/HSM, rotation, compromise) | tested by Astra; procedure undocumented | §5 preconditions |
| Sub-processors (embedding and LLM providers) | envelope axis in §0.1 | per-certificate declaration |
| Accessibility (Section 508) of dashboards | out of scope | stated |


## How to read a certificate against this appendix

1. Confirm the artifact's certificate is not expired (§5: any change to the watched
   surface set expires it; `scripts/check-cert-expiry.sh`) and carries a bundle whose
   `envelope_ref` equals the pinned declaration hash.
2. Confirm your backend, transport model, host range, topology, posture and external
   processors are INSIDE the §0.1 envelope, and your own SLO/RPO/RTO are inside the
   declared values of `v1.0.0-DECLARATION.md` §1–§4 on hardware not weaker than the
   qualification host named in the run record.
3. Read the label. A VENDOR SELF-CERTIFIED certificate is admissible only where your
   procurement rules allow it (§7).
4. For every row above marked `not written` / `not stated` / `NOT CERTIFIED`, treat the
   area as absent from the certificate; the row names where its evidence will land.
