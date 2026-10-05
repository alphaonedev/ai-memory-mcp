# Hero section — for the GitHub release page

Copy-pasteable markdown for the v1.0.0 release notes / GitHub release body.
Kept here so the release page and the kit cannot drift apart: if the lab
changes, this file changes with it in the same commit.

---
<!-- ── copy from here ────────────────────────────────────────────────── -->

## Run a hardened ai-memory federation on your laptop — one command

```bash
git clone https://github.com/alphaonedev/ai-memory-mcp
cd ai-memory-mcp
cargo build --release --bin ai-memory --example attest_sign
infra/federation-lab/run.py
```

That stands up **two v1.0.0 nodes federating over mutual TLS** on loopback,
loads a 300-row synthetic corpus, and then proves the thing works with
assertions instead of adjectives:

| | |
| --- | --- |
| ✅ | Both nodes answer over **mutual TLS with a fingerprint-pinned client cert** |
| ✅ | An **agent-attested** write is accepted on node A and stored `attest_level=agent_attested` |
| ✅ | That write **replicates across the quorum mesh** and arrives at node B still `agent_attested` |
| ✅ | **Federated recall** — node B, which never saw the request, returns the memory |
| ✅ | Corpus recall returns hits from the seeded namespace |
| ⛔ | A certificate signed by the **same CA** but absent from the allowlist is **refused** |
| ⛔ | **Plaintext** HTTP against the mTLS port is **refused** |
| ⛔ | An **unsigned** write is **refused** `403` under required attestation |
| ⛔ | `asi-hard` **refuses to boot** when a pinned knob is loosened — the no-disable contract, demonstrated |

```
   18 PASS / 0 FAIL

   federation lab GREEN — 18 assertions passed.
```

No cloud account, no Docker, no network egress, no `sudo`. Prereqs are
`python3` (3.9 or later), `openssl` and `bash`. The kit writes only inside its own
directory and cleans up after itself — including on Ctrl-C.

**Honest by construction.** The lab runs every `asi-hard` posture
knob at its hard floor, all of them. One knob,
`AI_MEMORY_REQUIRE_ROLLBACK_CHECK`, could not cold-boot a fresh node on older builds (no off-table
head anchor — [#2942](https://github.com/alphaonedev/ai-memory-mcp/issues/2942), fixed by PR #3096),
so the kit boots a node under the full profile on every run and requires it to come up (a refusal
is a failure; a timeout kill of a healthy node is never counted as a refusal). It also re-derives
the pinned-knob set from `src/security_profile.rs` on every run and goes red if the kit and the code
ever disagree.

Equally honest about scope: this is a **functional demonstration**, not a
benchmark. It reports no timings and measures no capacity. The v1.0.0
enterprise-federation certification is scoped to **500–1,000 agents and ≤50
peers**, and nothing here extends that.

📖 Full walkthrough, per-step explanation and troubleshooting:
[`infra/federation-lab/README.md`](infra/federation-lab/README.md)

<!-- ── copy to here ──────────────────────────────────────────────────── -->
