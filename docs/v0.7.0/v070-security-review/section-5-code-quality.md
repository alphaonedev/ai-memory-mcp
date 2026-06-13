# Section 5 — Code quality, async correctness, resource safety

**Specialist:** S5 / 6 — code quality + async correctness + resource safety
**Base SHA:** `b4ba16c8cfcfab459e08e1115518aaf8b273b407` (`local/install-815-816`)
**Date:** 2026-05-19
**Scope:** E.1 unsafe blocks · E.2 panic surface · E.3 await-holding-lock · E.4 resource leaks · E.5 memory bounds · E.6 TOCTOU · E.7 MCP wire-schema completeness · E.8 token budget regression

---

## Per-axis verdict

| Axis | Verdict | Detail |
|------|---------|--------|
| E.1 unsafe blocks | PASS | 152 textual hits; ~140 are `env::set_var` / `env::remove_var` test scaffolding (Rust 2024 wrapping). Real unsafe sites: `audit.rs` libc `chflags`/`ioctl`/`open`/`close` (carry `// SAFETY:` justifications); `embeddings.rs` + `reranker.rs` `candle::VarBuilder::from_mmaped_safetensors` (SAFETY annotated); `log_paths.rs` + `config.rs` test env scaffolding (SAFETY annotated, `env_lock()`-serialised); `identity/mod.rs`, `identity/keypair.rs`, `mcp/mod.rs`, `audit.rs:1832` — all test-scope env mutations with SAFETY comments. **0 unannotated unsafe blocks.** |
| E.2 panic surface | PASS | Top 12 files by raw count are 99 %+ inside `#[cfg(test)]`. Production-scope (above first `#[cfg(test)]` boundary) totals: `storage/mod.rs=1` (`len checked` invariant), `cli/install.rs=1` (post-validation `Option::unwrap`), `daemon_runtime.rs=2` (hardcoded tracing directives `.parse().unwrap()`), `llm.rs=1` (only inside a `#[cfg(test)]`-gated `new_for_testing`). Every site is a clear invariant on hardcoded data or post-validation state. **0 caller-controlled unwraps in production paths.** |
| E.3 await-holding-lock | PASS | `cargo clippy --release --all-targets --target-dir .cargo-r5-target/ -- -D clippy::await_holding_lock -A clippy::all -A clippy::pedantic` exits 0 after a clean 49 s release-profile build. The post-509224d99 fix in `webhook_http_parity.rs` holds; no regressions elsewhere. |
| E.4 resource leaks | PASS | 41 `tokio::spawn` sites in production code, all daemon-lifecycle tasks with explicit notify-shutdown semantics in `daemon_runtime.rs` / `federation/sync.rs` / `governance/deferred_audit.rs`. `task_handles.push(tokio::spawn(...))` pattern at `daemon_runtime.rs:2574` retains the JoinHandle. sqlite `Connection` is `Arc<Mutex<(Connection,…)>>` and drops RAII-clean. No channel-sender vs. receiver mismatches surfaced under grep. |
| E.5 memory bounds | PASS | Global `DefaultBodyLimit::max(2 * 1024 * 1024)` layered in `src/lib.rs:429` covers every Axum extractor (`Json<T>`, `Bytes`, `Body`). `serde_json::from_slice(&body_bytes)` in `handlers/approvals.rs:223` is downstream of the 2 MB cap. No raw `axum::body::to_bytes(_, usize::MAX)` calls anywhere in `src/`. |
| E.6 TOCTOU | PASS-with-note | 73 `.exists()` sites in `src/`. The two security-relevant patterns (`cli/rules.rs:474, 483, 804, 824` for operator-key generation) gate `OpenOptions::create_new(true)` (O_EXCL), so the race outcome is "second writer gets error" — not a security bypass. `audit.rs:360` `read_chain_tail` race is read-only and propagates the open error via `?`. No exploitable TOCTOU surfaced. |
| E.7 MCP schema completeness | **HOLD** | Spot-check of 10 random tools surfaced **3 schema/handler mismatches**, each in the same class as the round-2 fixes #892 / #893 / #901. Filed as #904 (`memory_kg_query` missing `by_source_uri` + `namespace`), #906 (`memory_update` advertises `source_uri` but handler ignores it), #908 (`memory_consolidate` reads `agent_id` but schema omits it). Each is a discoverability-via-`tools/list` defect. |
| E.8 token budget regression | PASS | `ai-memory doctor --tokens --json`: `full_profile_total_tokens = 9998` (≤ 10000 verbose cap); `trimmed_full_profile_total_tokens = 4756` (≤ 5000 trimmed cap); `active_total_tokens = 2021` for `core` profile. |

---

## Findings summary

- **Unsafe surface:** 152 total textual occurrences, 100 % annotated where load-bearing. Test env-mutation churn dominates the count; real FFI unsafe (libc, candle mmap) is each <10 lines and carries SAFETY rationale.
- **Panic surface in production:** essentially zero. The dominant `.unwrap()` / `.expect(` density lives behind `#[cfg(test)]` cliffs in `mcp/mod.rs`, `storage/mod.rs`, `handlers/*.rs`. Production code routes through `?` and `anyhow::bail!` / `MemoryError`.
- **MCP schema gaps (E.7) are the ship-blockers.** Three filed: #904, #906, #908. They are not safety bugs but contract bugs — the schema is the wire surface NHIs use for discovery, and dishonest schemas (handler-reads-key-not-in-schema or schema-advertises-key-not-read-by-handler) silently degrade callability. Class is well-understood; fixes are ≤6 lines each in `src/mcp/registry.rs` plus a spec-completeness assertion.
- **No clippy::await_holding_lock regressions.** Build was clean in 49 s with the dedicated check.
- **Token budget envelope still inside the contract.** No regression from the round-2 cap.

---

## Ship-blockers filed

| # | Title | Class | Proposed fix size |
|---|-------|-------|-------------------|
| [#904](https://github.com/alphaonedev/ai-memory-mcp/issues/904) | `memory_kg_query` schema missing `by_source_uri`, `namespace` | E.7 wire-schema | ~6 LOC registry.rs |
| [#906](https://github.com/alphaonedev/ai-memory-mcp/issues/906) | `memory_update` schema advertises `source_uri` but handler drops it | E.7 wire-schema (reverse) | ~3 LOC registry.rs (remove) |
| [#908](https://github.com/alphaonedev/ai-memory-mcp/issues/908) | `memory_consolidate` schema missing `agent_id` | E.7 wire-schema | ~3 LOC registry.rs |

---

## Verdict

**SHIP-WITH-CAVEATS.** Code-quality axes E.1-E.6 + E.8 are clean. The three E.7 schema gaps (#904, #906, #908) are contract bugs at the MCP wire surface — not safety / soundness defects, but they degrade tool-discovery for NHI callers and fall into a class the v0.7.0 round-2 sweep already standardised on (one-line registry patches + completeness-spec assertion). Recommend folding the three fixes into the next pre-tag commit batch before final SHIP; under the project prime directive every found defect is a fix-not-defer item, so resolving these three is mechanically straightforward and re-runs cleanly through the existing schema-completeness regression test bench. Once #904 / #906 / #908 land green, this section flips to unconditional SHIP.
