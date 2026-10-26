# PR #7393 red/green provenance correction

Recorded 2026-10-19 for [issue #7740](https://github.com/alphaonedev/ai-memory-mcp/issues/7740).

The r8 review of [PR #7393](https://github.com/alphaonedev/ai-memory-mcp/pull/7393)
identified an inaccurate file attribution in the lane READY report.
It described the red revision as changing both the r8 test file and the runtime
guard. The correct attribution is:

| Revision | Changed files relevant to the correction |
| --- | --- |
| Red [`33a0535cc46439926f16afd3ab614bc32f3b2ef2`](https://github.com/alphaonedev/ai-memory-mcp/commit/33a0535cc46439926f16afd3ab614bc32f3b2ef2) | Only `scripts/ci/tests/test_evidence_generator_r8_7393.py`: 683 insertions, zero deletions. |
| Green [`868465720b8d0c07016e9d90bffd0b430eccd77f`](https://github.com/alphaonedev/ai-memory-mcp/commit/868465720b8d0c07016e9d90bffd0b430eccd77f) | The r8 modifications to `scripts/ci/tests/tmp_runtime_guard_7393.py`, including additional audit-hook events and `_state_of`: 38 insertions, 19 deletions. This revision also changes seven other files. |

The guard already exists at the red parent
[`ce1509e279b650af905eb1359f629ba4346a5c1b`](https://github.com/alphaonedev/ai-memory-mcp/commit/ce1509e279b650af905eb1359f629ba4346a5c1b).
Its Git blob is `3925924666dc3a909596722d1821d35f26d454f8` at both
that parent and the red revision. The green revision changes that blob to
`b736d5d3d6dc6228dd17b501d0aac114607eba22`.
These identities, the red file list and the insertion/deletion counts are
verifiable from the immutable revisions linked above.

The red revision is an ancestor of green, which is an ancestor of reviewed
PR #7393 revision
[`f049ee0e4ec91ccd4ebc5273dfaa495f139cfcb4`](https://github.com/alphaonedev/ai-memory-mcp/commit/f049ee0e4ec91ccd4ebc5273dfaa495f139cfcb4).
That reviewed revision is also an ancestor of this record's base
[`4519f1645c9b9315f3981bf6aff5de90c670d310`](https://github.com/alphaonedev/ai-memory-mcp/commit/4519f1645c9b9315f3981bf6aff5de90c670d310).

Conductor `ai:god-f2` (GPT-6, Codex), acting on behalf of `alphaonedev`,
corrected the report's attribution sentence and recorded the correction in the
[PR #7393 review log](https://github.com/alphaonedev/ai-memory-mcp/pull/7393#issuecomment-6278472514).
The original report was preserved before correction. This record was authored
by `ai:codex-fix-7740` (GPT-6, Codex) under that conductor.

This correction concerns commit/file provenance only. It changes no runtime
behavior or tests, rewrites no Git history, and establishes no new red-test
result. Independent review and the complete stack's validation remain required
before landing.
