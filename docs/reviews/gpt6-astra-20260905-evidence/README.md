# GPT 6 Astra assessment evidence

Companions: [assessment](../GPT-6-ASTRA-FULL-SPECTRUM-ASSESSMENT-2026-09-05.md) and [proposed test plan](../GPT-6-ASTRA-AI-NHI-TEST-PLAN-2026-09-05.md).

Reviewed source: `87f86a0a1399d8282a60690ce463cba2ba688ebe`, release/v1.0.0, 2026-09-05. These records distinguish this session's execution, source inspection and historical test artifacts. Hashes bind captured bytes; they do not authenticate the historical producer, prove a running binary's source, or certify unexecuted tests.

## Coverage

- [Coverage summary](coverage-summary.json): exact census totals and method limits.
- [Documentation inventory](docs-coverage.csv): all 525 files, hashes, line/word counts and the full-read assignments for all 60 prior reviews/audits/designs/integrations. Other files received full-input lexical/structural screening and bounded per-file review, with additional direct reads recorded in the review notes. No claim that all 1.289 million documentation words received semantic line audit.
- [Issue inventory](issues-coverage.csv): all 2,406 retrieved open/closed issues, body/comment hashes, retrieved comment counts, reviewer and bounded-screen method. Raw bodies/comments remain in the local evidence workspace; they are not republished wholesale. Four comments advertised by API counters were not returned by direct requests either. Selected full-thread reads and corrections appear in `issues-review-*.md`.
- [Source inventory](source-coverage.csv) and [exact direct-read ledgers](source-direct-read-ledgers.json): every selected source/configuration line received lexical screening, while semantic inspection is limited to the documented ranges. The source-extension predicate is in the summary. It is not a complete dependency audit or a semantic review of all 976,142 selected lines. “Full function” does not mean every transitive helper or backend was verified.
- `previous-reviews-*.md` preserve historical-to-current reconciliation; `docs-sweep-*.md` preserve broader per-file analysis. Old claims and scores remain historical evidence, including superseded allegations.

## Direct execution

- [Root synthetic MCP calls](root-live-probes.json), [independent retrieval probe](retrieval-fidelity-live.json), [retrieval cleanup](retrieval-cleanup.json) and [root cleanup verification](root-cleanup-verification.json). Existing corpus content is excluded. Call timings are single observations, not service-level benchmarks. Root's installed binary hash is recorded separately from the reviewed source SHA; source/build equivalence was not established.
- [Repeated offload dereference](root-offload-dereference.json) preserves the follow-up exact-byte/SHA-256 check of the original synthetic payload. The initial dereference was observed but not retained in the root call-log file; this evidence is explicitly a later verification of the same offload.
- [Native-tier read-only proof](native-tier-proof.txt): PostgreSQL/AGE/pgvector, TLS and index observations. This is not end-to-end enterprise application or fault testing.
- [Capture response probe](capture-pending-probe.py) and [observations](capture-pending-probe.json): monkeypatches only the subprocess response seam while calling the real Python adapter functions. Run from the repository root with `python3 docs/reviews/gpt6-astra-20260905-evidence/capture-pending-probe.py`. It performs no production memory calls. A real governed transport test remains proposed.
- [Operations checks](operations-executed-checks.json): executed ledger and mutation checks, with reviewed versus merely inventoried build scripts distinguished.
- [GitHub release/protection snapshot](release-github-snapshot.json): the reviewed source's workflow outcomes and the protection state observed during assessment; not a new release or test dispatch.
- [Local publication checks](local-validation.json) and [authorized documentation publication procedure](publication-procedure.json). The temporary administrator exception authorized by the user is solely for documentation publication with CI skipping, not a product qualification result. Actual restoration is verified after the push; the pre-commit procedure file does not pretend that future action is already complete.

Review memories were deleted and their canonical gets returned not found. A synthetic action remains terminal/abandoned with its lease released; the offload had a one-hour TTL. No production restart, restore, cross-owner copy, purge, cloud deployment or destructive enterprise test was executed.

## Historical test data

Read-only SFTP/SSH retrieved f2's `/home/fate_two/v07/v09-dev/infra/cf-dashboard/public` JSON/HTML products and sibling publisher, plus selected underlying run artifacts. Published products are served at [the test dashboard](https://test.agenticmem.co/). The local capture manifest includes all seven products, their renderers and the inspected raw NHI/scaling/continuity/Big-10 artifacts.

- [Capture hashes](remote-capture-manifest.json) and [remote scaling/continuity hashes](f2-artifact-manifest-enterprise.json) identify the retained evidence and acquisition boundaries. Publisher code was read, not executed.
- [Displayed restart run](restart-artifacts/continuity-a56d9a.json) preserves the three manually transcribed card values; sibling files preserve failed and superseding runs. It demonstrates acknowledged-row retention across daemon kills, not model-state recovery or next correct business action.
- [Weighted NHI summary](weighted-nhi-summary.json) retains the structured FAIL verdict, 273-call reconciliation and strict mission counts. Full journals were analyzed locally; the source log hashes are in the capture manifest.
- `dashboard-enterprise.md`, `dashboard-retrieval.md` and `dashboard-security.md` preserve workload and evidence qualifications. Dashboard labels are not recast as completed mission postconditions.

Raw captured state can predate the page's publication timestamp and the reviewed source. No unseen or unrelated f2 scratch runs are implied to have been audited.

## Voting protocol

The seven named jurors A–G recur in all three waves. Root coordinates and is not a voting member. All use GPT 6 Astra; shared model/context/tools and later discussion create correlated judgments. New panelists did not read other ballots before their first investigation, but inherited task context. This is not a blinded or heterogeneous-model study.

`w1-*.md` are the seven retained first-wave investigations. `w2-fullpanel-*.md` record seven-way cross-examination. `w3-fullpanel-*.md` record final adjudication of both deliverables. Earlier three-juror cross-examination/provisional final rounds are excluded from the 21 required ballots. Initial claims remain visible with later corrections; a source-confirmed mechanism does not become runtime proof through voting.

The [final 21-ballot registry](ballot-registry.json) records file hashes and explicit votes. All seven final jurors accepted both documents. A NO and NOT PROVEN both withhold the broad readiness claim, but remain distinct judgments; they are not silently collapsed into unanimous defect findings.

The [finalization record](finalization.json) binds the published document bytes to the accepted snapshots and lists the permitted mechanical changes. [Bundle checksums](SHA256SUMS) cover every evidence file except the checksum file itself.
