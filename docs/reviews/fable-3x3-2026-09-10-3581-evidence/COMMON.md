# Common brief for every ballot (3x3 adversarial vote on ai-memory issue #3581)

You are one ballot in a 3x3 adversarial review. Judge the repository as a memory + coordination substrate. Do not inherit prior chat metaphysics. You have read-only access to the tree; run NO cargo, make NO edits, create NO files outside your answer.

Tree to inspect (read-only): <tree>  (chain-4 tip, aae5320e, v1.0.0 release development). Use grep/sed/cat only. Cite file:line for every claim you verified; say "not verified" for anything you did not.
Related issues you may read with `gh issue view <n> --repo alphaonedev/ai-memory-mcp`: 3581 (the assessment under vote), 3549, 3199, 3124, 3558, 3578, 3125, 3363, 3419.

The question: should ai-memory treat any part of itself as an "integrity kernel"? The Conductor's assessment (issue #3581, text provided) returned verdict B-sharpened: accept the position "a small integrity kernel (durable commit, writer attestation, authorization, schema, fork-safe apply) as an ENFORCED BOUNDARY, not a kernel-shaped product; no crate extraction during the v1.0.0 freeze; the boundary is #3549 (dispatch-level authority resolver + structural guard) + #3199 (signed restore) + #3124 (one caller-owns policy); extract a core module/crate in v1.1.0 once the guard proves the boundary."

Verdict letters: A = extract/name a core crate now (store, attest, authz, schema, apply); B = agree in principle, defer extraction, land the boundary (the assessment's position); C = reject: wrong abstraction, fix specific write paths, no "kernel"; D = stronger: kernel necessary AND current federation/restore unsafe until apply is signed and gated.

Ballot format (max 650 words, markdown):
## Ballot <your id>
**Vote:** A | B | C | D  (one letter, then one sentence)
**Verified evidence (file:line):** 4-8 bullets
**Where the assessment is wrong or overstated:** bullets (or "none found")
**Where the assessment is right:** bullets
**Required amendments to #3581 before acceptance:** numbered, concrete
**One risk if followed / one risk if ignored:** two lines
