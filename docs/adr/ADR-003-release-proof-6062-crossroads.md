---
layout: doc
---
# ADR-003 — Release-proof crossroads for #6062: drop the Intel macOS leg, keep the shipped-artifact bind, bind assert inputs by content hash

Status: **ACCEPTED + IMPLEMENTED**

Date: 2026-10-09
Author: Claude Opus 5.5 on behalf of @alphaonedev
Decision record: ai-memory memory `85d352fe` (round-2 votes for #6062;
crossroads policy `4d3ea1c5`, 5-agent vote per decision). Lenses for every
decision: precedent / spec-literalism / client-compat / testability /
blast-radius.
Related: #6062 (umbrella), #6294 (record these votes), #4770, #4752, #4768,
#6275, #6279, #6287, #2728.
Spec SSOT: `.github/workflows/release.yml`, `scripts/check_release_features.py`
(`RELEASE_TARGETS`, the bind and assert step pins).

---

## Context

Round 2 of the #6062 release-proof work reached three points where at least
one crossroads trigger held. D1 is a T6 choice between mutually exclusive
release matrices. D2 and D3 were decided in round 1 without a recorded vote
and are re-run retroactively here: D2 is a T3 security-posture choice, and D3
is a T3 choice plus a T5 deviation from the literal `git diff` wording of #4768.

## Decision

### D1 (#4770, T6): drop the x86_64-apple-darwin release artifact (3-2)

| lens | verdict | confidence |
|---|---|---|
| precedent | drop | 0.62 |
| spec-literalism | drop | 0.68 |
| client-compat | Rosetta leg | 0.72 |
| testability | drop | 0.72 |
| blast-radius | Rosetta leg | 0.68 |

The three remaining legs (x86_64 and aarch64 linux-gnu, aarch64-apple-darwin)
each run the strict exact-set assert natively on their own ISA with no
conditional path. Folded in from the minority: the guard pins
`RELEASE_TARGETS` to exactly three (target, os) pairs and refuses an
x86_64-apple-darwin leg. The Homebrew formula declares `depends_on arch:
:arm64`, so an Intel Mac gets a clear refusal instead of a wrong-arch
download. Every consumer surface changes in the same commit. No lens chose a
self-hosted Intel runner, because it would hold release write grants
(#6279). Implemented by `fix(#6279,#6287): pin release (target, os) pairs;
drop x86_64-apple-darwin`.

### D2 (#4752, T3, retroactive): keep the shipped design, the shipped artifact is bound to the asserted binary (5-0)

All five lenses chose A (sum confidence 3.60) over B (asserting on `dist/`
directly). The blast-radius top risk, a `GITHUB_PATH`/`GITHUB_ENV` shim of
the compare tools, is closed by the D3 winner and by #6274, which compares
the reproducible job's hash with the shipped Linux x86_64 artifact.
Implemented by `fix(#4752): bind the shipped artifact to the binary the
strict assert checked`.

### D3 (#4768 and #6275, T3 and T5, retroactive): bind the assert's inputs by content hash in a sanitized shell (5-0)

All five lenses chose C (sum confidence 3.78). The bind and the assert run
under `env -i` with a fixed absolute `PATH` and a bash that reads no startup
file. Each bound file's `git hash-object --no-filters` must equal the blob at
the verified sha, and `HEAD` must equal the preflight sha. The Dockerfile
checks the copied declaration and asserter against digests that the guard
recomputes from the tree. The hash-object form deviates from the literal
`git diff` wording of #4768, and this vote records that deviation (T5).
Implemented by `fix(#4768): bind the strict assert's inputs to the checked-out
commit`, `fix(#6275): bind the assert inputs in a sanitized shell by content
hash` and `fix(#6277): Dockerfile build RUN checks the declaration and
asserter sha256`.

### D4 (#6908, T3, same defect class failed review twice): pin the bound files' SHA-256 in the workflow text (3-0)

`3-agent vote (6def5ab6)`, memory `af6af3b1`. D3 read the expected blob
from the job's own `.git`, which an earlier step can rewrite: a forged
loose tree, an exploded pack, an alternate object store, a gitfile or a
symlinked `.git` each forged the expected value together with the file.
Option A won 3-0 over B (GitHub REST contents at the preflight sha) and C
(fetch the preflight sha into a fresh private repository): every bind now
pipes `echo "<sha256> *<file>"` lines, pinned in the workflow text, to
`/usr/bin/shasum -a 256 -c -` and still requires `HEAD` to be the preflight
sha. The guard recomputes each digest from the tree it checks
(`BIND_SUMMED`, the #6277 Dockerfile precedent) and refuses a stale pin or a
pin of an unbound file, so a bound-file edit lands with its pin in the same
commit. A tag whose bound files differ from the dispatch tip fails closed.
The window between the bind and the interpreter opening the file, and a
step able to replace `/usr/bin` tools, are the runner-trust boundary and
are tracked as a residual issue.

## Consequences

- Intel macOS users build from source. The release no longer publishes an
  Intel macOS binary that it cannot assert natively.
- A later edit that loosens the shipped-artifact bind, the sanitized shell or
  the content-hash compare is refused by `scripts/check_release_features.py`,
  and its mutation sweep keeps every refusal load-bearing.

## Alternatives rejected

- D1: a Rosetta 2 leg on Apple Silicon (two votes). Its pass is not proof on
  real Intel hardware, it adds a network fetch to a job holding attestation
  grants, and it reintroduces the #2728 Rosetta dependency. A self-hosted
  Intel runner (zero votes).
- D2: B, asserting on `dist/` itself. It has a smaller surface, but it moves
  the assert away from the binary the build step produced.
- D3: B, a literal `git diff --exit-code` bind. It reads the index, so an
  index-state edit (assume-unchanged, skip-worktree) passes it. D, a job with
  no third-party actions, removes the on-runner surface but rebuilds the
  release job.
