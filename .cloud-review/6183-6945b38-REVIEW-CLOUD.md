# Cloud review PR #6183 head 6945b38c6: VERDICT APPROVE

Lane `rev-6183` (cloud sandbox, read-only adversarial review for ai:god-f1).
Subject: draft PR #6183 `fix(#6157): negotiate MCP protocolVersion against
SUPPORTED_PROTOCOL_REVISIONS`, head `6945b38c6f71539a9636eb5ab4ef87389c11469a`,
base `chain/promo6-ssh` = `fa6b588e6b5dfa97370b4f073e60e66cb1ed1fa7`, 15 files
+423/-17 (`git diff fa6b588e..6945b38c6 --stat` reproduced in the sandbox).

Verdict rationale: the negotiation itself is spec-conformant (2024-11-05 and
2025-03-26 Lifecycle §Version Negotiation, quoted below), total, panic-free on
every hostile input tried, red-first with the red reproduced on the base
sources, and the SSOT walk is non-vacuous (29 pinned uses, guard `>= 15`).
Three findings remain; none is a correctness defect in the diff. F1 is a scope
gap the PR itself leaves open and should be fixed before or immediately after
merge (shipped client shims and cookbook scripts outside the SSOT walk still
send `2025-03-26` and now draw a downgrade line on every spawn). F2 and F3 are
pre-existing defects surfaced by the review, listed for f1 to file.

## Findings

Ranked by severity. Severity scale: HIGH = wrong behaviour on the wire;
MEDIUM = shipped artefact drifts from the fix / operator-visible noise;
LOW = hygiene.

### F1 (MEDIUM) — the SSOT walk stops at `tests/ src/ docs/ scripts/`; 14 shipped client / cookbook / bench literals still send `2025-03-26` and are downgraded with a stderr line on every spawn

- Where: `tests/mcp_protocol_revision_ssot_6157.rs:28` (`ROOTS = ["tests", "src", "docs", "scripts"]`) and `:29` (`EXTENSIONS` has no `ts` / `mjs`).
- What: the PR's own rule is "every fixture and doc that names a `protocolVersion` is inside the list" (`src/mcp/jsonrpc.rs:53-54`), but the walk never visits `clients/`, `cookbook/`, `benches/`. Those trees carry 14 `protocolVersion` literals that the tip no longer echoes:
  - `clients/anthropic-shim-py/ai_memory_anthropic_shim/_capture.py:45` `2025-03-26`
  - `clients/anthropic-shim-ts/src/index.ts:78` `2025-03-26`
  - `clients/openai-shim-py/ai_memory_openai_shim/_capture.py:39` `2025-03-26`
  - `clients/openai-shim-ts/src/index.ts:80` `2025-03-26`
  - `clients/host-adapter-shim/python/capture_turn.py:133` `2025-03-26`
  - `clients/host-adapter-shim/node/capture-turn.mjs:118` `2025-03-26`
  - `clients/host-adapter-shim/bash/capture-turn.sh:172` `2025-03-26`
  - `clients/host-adapter-shim/tests/envelopes.py:165` `2025-03-26` (fake-server fixture: the shim conformance table asserts against a server answer the real server never gives)
  - `cookbook/recursive-learning/01-bounded-recursive-refinement.sh:130`, `02-curator-driven-reflection.sh:149`, `03-reflection-to-skill-promote.sh:93`, `04-forensic-bundle.sh:89`, `05-autoresearch-composition.sh:97` `2025-03-26`
  - `benches/harness_bench.rs:210` `2025-03-26`
- Effect on the tip: every one of these clients is answered `2024-11-05` (same as on the base, so no wire regression) AND now produces one `ai-memory: MCP initialize downgrade: client protocolVersion "2025-03-26" is not supported; ...` stderr line per spawn. The host-adapter shims forward the child's stderr to the end user on every non-persisted outcome (`clients/host-adapter-shim/python/capture_turn.py:319-326`, `node/capture-turn.mjs:329-339`), so the diagnostic reaches operators of the shipped shims, who cannot act on it (the client is the project's own).
- How reproduced: `python3 -I .local-runs/rev-6183/count_uses.py $PWD` re-implements the test's marker + date scan: walked roots `files=2413 uses=29 offenders=[]`; unwalked roots (`clients cookbook benches sdk infra examples`) `uses=17`, 11 of them `2025-03-26` (the three `.ts`/`.mjs` literals are invisible even to that scan because the extension list omits them).
- Fix size: 14 one-token edits (`2025-03-26` -> `2024-11-05`, or read the SSOT where the language allows) + extend `ROOTS` with `clients`, `cookbook`, `benches` and `EXTENSIONS` with `ts`, `mjs` (~4 lines in the test). ~20 lines total. Can land in this PR (same issue, same rule) or as the first follow-up to #6157.

### F2 (LOW, pre-existing, not introduced by this PR) — `run_mcp_server` panics (exit 101) when the host closes the server's stderr pipe; the server dies before serving `initialize`

- Where: `src/mcp/mod.rs:5097` (`eprintln!("ai-memory MCP server started ...")`), and the #3354 key-generation line before it; the new `eprintln!` at `src/mcp/mod.rs:3565` copies this precedent.
- What: Rust `eprintln!` panics on a write error other than EBADF. A host that spawns the server with a stderr pipe and drops the read end gets a dead server with zero stdout. The PR's downgrade line cannot make this worse because the startup banner already hits the broken pipe first.
- How reproduced: `python3 -I .local-runs/rev-6183/probe_stderr_closed.py <tip> tip-closed-supported 2024-11-05 ...` -> `rc=101 stdout=b''`; same with `2099-01-01` -> `rc=101 stdout=b''`. Identical outcome for supported and unsupported revision proves it pre-dates the diff.
- Fix size: route the stdio-loop stderr writes through a `writeln!(std::io::stderr(), ...)` whose error is ignored (one helper, ~10 lines, ~40 call sites in `run_mcp_server`). Separate issue.

### F3 (LOW, pre-existing, not introduced by this PR) — a JSON-RPC batch array is refused with a misleading `-32700` message

- Where: `src/mcp/mod.rs:5334-5346` (`serde_json::from_str::<RpcRequest>` error text goes straight into the response).
- What: the PR's decision record rests on "the stdio loop answers a JSON array with `-32700`". Confirmed, but the message is `parse error: invalid type: map, expected a string at line 1 column 1`, which names serde's internal expectation, not "batch not supported". A client author debugging a 2025-03-26 batch gets no hint.
- How reproduced: probe case `batch_array` -> `{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error: invalid type: map, expected a string at line 1 column 1"}}`.
- Fix size: one `if line.trim_start().starts_with('[')` arm before the decode returning `-32700` "JSON-RPC batch not supported (revision 2024-11-05)" + one test, ~15 lines. Separate issue; it is also the natural place to hang the 2025-03-26 audit.

### Observations that are not findings

- `negotiate_protocol_revision` treats `params` that is not an object (e.g. `"params": "2024-11-05"`) as `<missing>`; the spec requires `params` to be an object, so collapsing it to the downgrade path is correct.
- The 64-char clip happens before `{:?}` escaping, so the escaped echo can exceed 64 bytes (max observed 199-char line; theoretical bound 64 x 10 bytes for `\u{...}` escapes plus the fixed text). Bounded, and the PR body says "at most 64 escaped chars of the client value", which is loose wording, not a defect.
- `README`/docs wording in the diff states exactly the implemented rule (see lens 8).

## Evidence

Sandbox: 4 cores, 15 GiB, rustc 1.98.0 via rustup (`rust-toolchain.toml` pin; `rustfmt` and `clippy` components were absent and were installed with `rustup component add --toolchain 1.98.0-x86_64-unknown-linux-gnu rustfmt clippy`), SQLite only. All scratch under `.local-runs/rev-6183/`.

### 1. Spec conformance

- `WebFetch https://modelcontextprotocol.io/specification/2024-11-05/basic/lifecycle` and `.../2025-03-26/basic/lifecycle` (identical normative text, quoted in §Spec citation).
- Result: CONFORMANT. The server echoes a supported request (`MUST respond with the same version`), otherwise answers `2024-11-05`, which is "another protocol version it supports" and is the latest it supports (`SHOULD be the latest version supported by the server`). The spec does not require an error; the `-32602 Unsupported protocol version` block on the same page is an example under "Error Handling", not a requirement. Not erroring is the literal rule.
- `WebFetch https://modelcontextprotocol.io/specification/2025-03-26/basic/index`: "MCP implementations **MAY** support sending JSON-RPC batches, but **MUST** support receiving JSON-RPC batches." Confirms the author's reason for not listing `2025-03-26`.
- `WebFetch https://modelcontextprotocol.io/specification/2025-06-18/changelog`: major change 1 is "Remove support for JSON-RPC batching". So the batch objection does not carry to `2025-06-18`; that revision stays unlisted only because it is unaudited (author says so). Recorded under FOUND-NOT-FIXED as the residual of #6157's headline.

### 2. Issue conformance

- Issue body read through the GitHub MCP tool (`mcp__github__issue_read #6157`); `gh` is not authenticated in this sandbox, the MCP path worked. Table in §Issue requirements. Vote assessment in §Vote assessment.

### 3. Hostile input on the wire

- Build: `cargo build --bin ai-memory` -> `Finished \`dev\` profile [unoptimized + debuginfo] target(s) in 4m 26s` (binary copied to `.local-runs/rev-6183/ai-memory-tip`).
- `python3 -I .local-runs/rev-6183/probe.py --binary .../ai-memory-tip --sandbox .../probe-sandbox` (full output in `.local-runs/rev-6183/probe-tip.out`). Every case: `rc=0`, exactly one stdout line, exactly one downgrade line when expected, no panic:

| case | stdout `protocolVersion` / error | downgrade lines | diagnostic (clipped) |
|---|---|---|---|
| supported `2024-11-05` | `2024-11-05` | 0 | none |
| 1 MiB string | `2024-11-05` | 1 | len 199: `client protocolVersion "AAAA...(64 A)" is not supported; responding with 2024-11-05 (supported: ["2024-11-05"])` |
| 900 KiB string | `2024-11-05` | 1 | len 199, 64-char clip |
| control chars + ANSI `\x1b[31mRED\x1b[0m\x07\x00\x7f` | `2024-11-05` | 1 | len 170: `"\u{1b}[31mRED\u{1b}[0m\u{7}\0\u{7f}"` (escaped, no raw ESC) |
| embedded `\n` / `\r\n` | `2024-11-05` | 1 | len 171: `"x\nai-memory: FORGED second line\r\n"` (escaped; stderr stays ONE line, no forged line) |
| `null` | `2024-11-05` | 1 | len 145: `<non-string>` |
| number `20241105` | `2024-11-05` | 1 | `<non-string>` |
| array | `2024-11-05` | 1 | `<non-string>` |
| object | `2024-11-05` | 1 | `<non-string>` |
| field missing | `2024-11-05` | 1 | len 142: `<missing>` |
| `params` missing | `2024-11-05` | 1 | `<missing>` |
| `params` is a string | `2024-11-05` | 1 | `<missing>` |
| 63 x `é` + `Z` + tail | `2024-11-05` | 1 | len 199: clip is char-based (63 `é` + `Z`), no mid-codepoint cut |
| invalid UTF-8 bytes in the line | `-32700 parse error: invalid UTF-8: invalid utf-8 sequence of 1 bytes from index 75` | 0 | none (rejected before dispatch, `src/mcp/mod.rs:5316-5328`) |
| batch array `[{initialize}]` | `-32700 parse error: invalid type: map, expected a string at line 1 column 1` | 0 | none (F3) |
| stderr pipe closed, `2099-01-01` | no stdout | n/a | `rc=101` (panic) — F2, pre-existing |

- Control for F2: `probe_stderr_closed.py ... tip-closed-supported 2024-11-05` -> `rc=101 stdout=b''` (same as unsupported).
- Non-downgrade stderr lines per spawn: 6 (key-gen notice, tier, profile, started, stopped...), unchanged from base; the diagnostic adds exactly one.

### 4. Red-on-base and green-on-tip

- `AI_MEMORY_NO_CONFIG=1 cargo test --test mcp_protocol_negotiation_6157 --test mcp_protocol_revision_ssot_6157` (tip) -> `test result: ok. 7 passed; 0 failed` (negotiation, 4 issue tests + 3 mcp_wait leaf tests) and `test result: ok. 3 passed; 0 failed` (ssot)
- `AI_MEMORY_NO_CONFIG=1 cargo test --lib jsonrpc_handles_initialize` -> `test mcp::tests::test_jsonrpc_handles_initialize ... ok` / `test result: ok. 1 passed; 0 failed; 8975 filtered out`
- `AI_MEMORY_NO_CONFIG=1 cargo test --test integration initialize` -> `test test_mcp_initialize ... ok` / `test result: ok. 1 passed; 0 failed; 218 filtered out`
- `git checkout ce1066061478a044186cbdc66f20ccf7a2ccb238 -- src && AI_MEMORY_NO_CONFIG=1 cargo test --no-fail-fast --test mcp_protocol_negotiation_6157` -> does NOT compile: `error[E0425]: cannot find value NEWEST_PROTOCOL_REVISION in module ai_memory::mcp::jsonrpc` (the HEAD shared fixture `tests/common/mcp_stdio_child.rs:117` reads the SSOT constant that base `src` lacks). Faithful red with the red commit's own fixture: `git checkout ce1066061 -- src tests/common/mcp_stdio_child.rs && AI_MEMORY_NO_CONFIG=1 cargo test --no-fail-fast --test mcp_protocol_negotiation_6157` -> `test result: FAILED. 4 passed; 3 failed` — failing: `issue_6157_unsupported_revision_gets_newest_supported_with_diagnostic` (`:98`), `issue_6157_missing_protocol_version_gets_newest_supported_with_diagnostic` (`:109`), `issue_6157_non_string_protocol_version_gets_newest_supported_with_diagnostic` (`:126`); all three on the missing stderr diagnostic, exactly as the PR body states
- `AI_MEMORY_NO_CONFIG=1 cargo test --test mcp_protocol_revision_ssot_6157` (base src) -> does not compile: `error[E0432]: unresolved imports ai_memory::mcp::jsonrpc::NEWEST_PROTOCOL_REVISION, ...SUPPORTED_PROTOCOL_REVISIONS, ...negotiate_protocol_revision` (+7 follow-on errors) — matches the PR body
- `git checkout HEAD -- src` restored; `git status --short` clean apart from this review file.

### 5. Vacuity of the SSOT walk

- Static: `tests/mcp_protocol_revision_ssot_6157.rs:92` asserts `files.len() > 100` and `:115` asserts `uses >= 15`, so an empty walk or a walk that matches nothing fails. `walk()` uses `fs::read_dir` + `path.is_dir()` (follows symlinks) but `find tests src docs scripts -type l` -> no symlinks exist; `target/` and `.local-runs/` are not under any root.
- Independent count (`count_uses.py`, same markers/date regex): `walked roots: files=2413 uses=29 offenders=[]`. The test's `>= 15` floor leaves headroom of 14 before a future deletion trips it; acceptable.
- Mutation: `sed -i 's/"protocolVersion": "2024-11-05"/"protocolVersion": "2025-03-26"/' tests/harness_integration.rs && AI_MEMORY_NO_CONFIG=1 cargo test --test mcp_protocol_revision_ssot_6157` -> `test issue_6157_every_protocol_version_use_is_a_supported_revision ... FAILED` with offender line `tests/harness_integration.rs:93: 2025-03-26`; `test result: FAILED. 2 passed; 1 failed`. The pin catches a single drifted fixture; `git checkout HEAD -- tests/harness_integration.rs` restored.

### 6. Behaviour change for real clients

- Base binary (`git checkout fa6b588e -- src && cargo build --bin ai-memory`, copied to `ai-memory-base`): `python3 -I .local-runs/rev-6183/probe_base.py` -> `base_2025_03_26 rc=0 protocolVersion=2024-11-05 stderr_lines=6 downgrade_lines=0`; `base_2024_11_05 ... protocolVersion=2024-11-05 downgrade_lines=0`; `base_missing ... 2024-11-05 downgrade_lines=0`; `base_2026_07_28 ... 2024-11-05 downgrade_lines=0`. The base answered `2024-11-05` to every client, silently
- Tip binary, client sends `2025-03-26`: answered `2024-11-05` + one downgrade line (probe case list above; `tests/mcp_protocol_negotiation_6157.rs:88-100` pins it).
- Net: identical wire answer on base and tip for every client; the only observable delta is the stderr line. Clients still sending a revision the tip does not echo: the 14 sites in F1 (`clients/` 8 incl. the fake-server fixture, `cookbook/recursive-learning/` 5, `benches/` 1). `sdk/`, `infra/`, `examples/` carry no `protocolVersion` literal (`rg protocolVersion sdk infra examples` -> none).

### 7. Production code hygiene

- `rg -n 'unwrap\(|expect\(|panic!|\[0\]' src/mcp/jsonrpc.rs` (new hunk `:40-110`) -> none. `src/mcp/mod.rs:3559-3576` (initialize arm) -> none. `SUPPORTED_PROTOCOL_REVISIONS[0]` index-by-position appears only in tests (`src/mcp/mod.rs:8758`, `tests/integration.rs:2142`), where a panic is the right failure.
- `cargo fmt --all --check` -> exit 0 (after installing `rustfmt`; the first run failed only with `'cargo-fmt' is not installed`).
- `cargo clippy --all-targets -- -D warnings -D clippy::all -D clippy::pedantic` -> `Finished dev profile [unoptimized + debuginfo] target(s) in 4m 35s`, exit 0, zero warnings (default features)
- `bash scripts/check-count-assertion-declared.sh --range origin/chain/promo6-ssh..HEAD` -> `count-assertion-declared: clean (origin/chain/promo6-ssh..HEAD)`, exit 0

### 8. Docs drift

- `docs/DEVELOPER_GUIDE.md:111`: states negotiation against `SUPPORTED_PROTOCOL_REVISIONS`, current list `["2024-11-05"]`, echo-if-member, newest-on-downgrade, stderr diagnostic, and the batch reason. Matches `src/mcp/jsonrpc.rs:40-110` and `src/mcp/mod.rs:3563-3570` exactly.
- `docs/integration-guide.md:301-305`: "speaks MCP 2024-11-05 protocol (the full supported set is `SUPPORTED_PROTOCOL_REVISIONS` ...; unsupported or missing `protocolVersion` is answered with the newest supported revision and a stderr downgrade diagnostic)". Matches. It omits the non-string case but points at the SSOT; acceptable.
- `rg -n '2025-03-26|2025-06-18|2026-07-28' docs/` -> only review/audit transcripts dated by those strings and `docs/reviews/*` tables; no doc claims a newer revision is supported. `docs/integrations.html:528` describes the handshake without a revision. `docs/audience/developer.html:108` sends `2024-11-05`. No drift inside `docs/`.
- Drift OUTSIDE `docs/`: `clients/*/README.md` do not name a revision; the code literals in F1 are the drift.

## Issue requirements

Source: #6157 body ("Proposed fix" and "Why this is a defect").

| # | Literal requirement in #6157 | Status | Evidence |
|---|---|---|---|
| R1 | Replace the single const with `SUPPORTED_PROTOCOL_REVISIONS: &[&str]` | MET | `src/mcp/jsonrpc.rs:56` |
| R2 | List "at minimum `2024-11-05`" | MET | `src/mcp/jsonrpc.rs:56,61` |
| R3 | "plus `2025-03-26` once the tool-result convention ... is verified end to end" | MET (conditional not triggered) | author audited and documented why not: batch receipt MUST (`src/mcp/jsonrpc.rs:48-51`); confirmed against spec text (lens 1) |
| R4 | Add `2025-06-18` / `2026-07-28` "only behind a verified behaviour audit" | MET (not added, audit not done) | PR body "not audited and are not listed"; residual listed in FOUND-NOT-FIXED |
| R5 | initialize arm reads `req.params["protocolVersion"]`; echo if supported | MET | `src/mcp/mod.rs:3563`, `src/mcp/jsonrpc.rs:80-93`; probe case `supported` |
| R6 | else respond with the newest supported revision | MET | `src/mcp/jsonrpc.rs:92`; probe cases 2-12 |
| R7 | Emit a stderr diagnostic on downgrade | MET | `src/mcp/mod.rs:3564-3569`; probe: exactly one line |
| R8 | Red-first test per branch: exact echo / unsupported / missing | MET | `tests/mcp_protocol_negotiation_6157.rs:73,83,105` (+ non-string `:117`); red commit `ce106606` |
| R9 | SSOT pin: every `tests/**/*.rs` and `docs/**/*.md` `20xx-xx-xx` MCP revision is a member of the list | MET (and extended to `src/`, `scripts/`) | `tests/mcp_protocol_revision_ssot_6157.rs:28` |
| R10 | Docs `DEVELOPER_GUIDE.md:111`, `integration-guide.md:301` list the supported set | MET | lens 8 |
| R11 | `changelog.d/<N>.fixed.md` | MET | `changelog.d/6157.fixed.md` |
| R12 | Headline defect 1: a `2026-07-28`-only client "terminates the session after initialize" | NOT MET by this PR (explicitly left open) | the tip still answers `2024-11-05` to such a client; this is the issue's conditional R4 and is a follow-up audit, not a defect in the diff |
| R13 | Headline defect 2: server "silently accepts any client revision ... without downgrading explicitly" | MET | downgrade is explicit on the wire and on stderr |
| R14 | Headline defect 3: 21-file duplication with no SSOT test | MET for the walked roots; NOT MET for `clients/ cookbook/ benches/` | F1 |

Is advertising only `2024-11-05` what the issue asked for? Yes: the issue's own text makes every newer revision conditional on a verified audit and says "keep the list truthful and no vote is needed". The PR honours the condition and documents the audit result for `2025-03-26`.

## Spec citation

MCP specification, revision 2024-11-05 and revision 2025-03-26, "Lifecycle" > "Initialization" > "Version Negotiation" (identical text in both, fetched 2026-10-09 from `modelcontextprotocol.io/specification/<rev>/basic/lifecycle`):

> In the `initialize` request, the client **MUST** send a protocol version it supports. This **SHOULD** be the *latest* version supported by the client.
>
> If the server supports the requested protocol version, it **MUST** respond with the same version. Otherwise, the server **MUST** respond with another protocol version it supports. This **SHOULD** be the *latest* version supported by the server.
>
> If the client does not support the version in the server's response, it **SHOULD** disconnect.

PR behaviour against each sentence: echo on member (MUST, met: `jsonrpc.rs:90-91`); another supported version otherwise (MUST, met: `jsonrpc.rs:92`); the latest the server supports (SHOULD, met: `NEWEST_PROTOCOL_REVISION` is pinned to index 0 and the list is asserted strictly newest-first at `tests/mcp_protocol_revision_ssot_6157.rs:140-147`). The spec never requires an error response for an unsupported client version; the `-32602` block on the same page is an illustrative "Example initialization error" under "Error Handling". CONFORMANT.

Revision 2025-03-26, "Overview" > "Messages" > "Batching": "MCP implementations **MAY** support sending JSON-RPC batches, but **MUST** support receiving JSON-RPC batches." The tip answers a batch array with `-32700` (probe case `batch_array`), so listing `2025-03-26` would claim an unimplemented MUST. The author's rationale is correct.

## Vote assessment

Was a 5-agent crossroads vote due (CLAUDE.md `4d3ea1c5` triggers)? **No.**

- T1 (public-contract shape change with >= 2 viable forms): no. `protocolVersion` already existed in the `initialize` result; its type and position are unchanged; the only new public items are constants and two pure functions in `jsonrpc.rs`, no trait, route, tool or schema change.
- T2 (sync/async boundary): not touched.
- T3 (security / governance posture): no. Downgrade-not-error is the spec's MUST, not a fail-open vs fail-closed choice the project makes; the diagnostic is bounded and escaped; no gate relaxed.
- T4 (hard-to-reverse representation): no persisted or signed bytes change.
- T5 (deviation from written spec / acceptance criterion): no. The issue's acceptance text is conditional ("plus `2025-03-26` once ... verified"; newer ones "only behind a verified behaviour audit") and itself states "keep the list truthful and no vote is needed". Not listing `2025-03-26` after an audit that found an unimplemented MUST is compliance with that condition.
- T6 (>= 2 mutually exclusive paths with no precedent): no. The spec prescribes the single path; the codebase precedent for the diagnostic is the existing `eprintln!("ai-memory: ...")` family in `run_mcp_server` (`src/mcp/mod.rs:3952,3965,5097`).

The PR body's "no T1 vote" decision record is correct and sufficiently argued.

---

REPORT lane=rev-6183 branch=cloud/f1/rev-6183 base=fa6b588e6b5dfa97370b4f073e60e66cb1ed1fa7 head=<the commit carrying this file; sha in the lane's final REPORT> pushed=yes
COMMITS
<sha> review(#6157): cloud adversarial review of PR #6183 head 6945b38c6
ITEMS
#6157 | reviewed | APPROVE | 3 findings (F1 MEDIUM scope gap fixable in-PR; F2, F3 LOW pre-existing)
GATES
cargo fmt --all --check -> exit 0 (clean)
cargo clippy --all-targets -- -D warnings -D clippy::all -D clippy::pedantic -> `Finished dev profile [unoptimized + debuginfo] target(s) in 4m 35s`, exit 0, zero warnings (default features)
AI_MEMORY_NO_CONFIG=1 cargo test --test mcp_protocol_negotiation_6157 --test mcp_protocol_revision_ssot_6157 -> `test result: ok. 7 passed; 0 failed` (negotiation, 4 issue tests + 3 mcp_wait leaf tests) and `test result: ok. 3 passed; 0 failed` (ssot)
AI_MEMORY_NO_CONFIG=1 cargo test --lib jsonrpc_handles_initialize -> `test mcp::tests::test_jsonrpc_handles_initialize ... ok` / `test result: ok. 1 passed; 0 failed; 8975 filtered out`
AI_MEMORY_NO_CONFIG=1 cargo test --test integration initialize -> `test test_mcp_initialize ... ok` / `test result: ok. 1 passed; 0 failed; 218 filtered out`
bash scripts/check-count-assertion-declared.sh --range origin/chain/promo6-ssh..HEAD -> `count-assertion-declared: clean (origin/chain/promo6-ssh..HEAD)`, exit 0
DECISIONS
Branch name: the harness pre-created `claude/cloud-lane-rev-6183-4p2sdr`; the lane brief names `cloud/f1/rev-6183` as the only branch to push, so the review branch and push target follow the brief (precedent: brief §"Your branch").
L1 memory_store rule (CLAUDE.md): no `mcp__memory__*` tool is attached to this sandbox session (ToolSearch "+memory store" -> no match), so the directive could not be stored in the substrate; this file is the durable record.
Review-only lane: no production, test or doc file was modified; the SSOT mutation and red-on-base runs were performed on the working tree and reverted with `git checkout HEAD -- <path>` (tree clean, verified with `git status --short`).
`cargo test --lib` full suite not run: the lane brief scopes lens 4 to the two new test files plus the lib initialize test and `tests/integration.rs` initialize tests, and the sandbox spent its cargo budget on clippy pedantic (--all-targets) and two full debug builds (tip + base).
FOUND-NOT-FIXED
tests/mcp_protocol_revision_ssot_6157.rs:28-29 SSOT walk omits `clients/`, `cookbook/`, `benches/` and the `ts`/`mjs` extensions; 14 shipped literals still send `2025-03-26` (F1, file list above) and draw a downgrade line on every spawn.
clients/host-adapter-shim/tests/envelopes.py:165 fake-server fixture answers `protocolVersion: 2025-03-26`, a value the real server never returns; shim conformance table is pinned to a non-existent server behaviour.
src/mcp/mod.rs:5097 (and every `eprintln!` in `run_mcp_server`) panics with exit 101 when the host closes the stderr pipe (EPIPE); the MCP server dies before `initialize` (F2, pre-existing).
src/mcp/mod.rs:5334-5346 a JSON-RPC batch array is refused with `-32700 "invalid type: map, expected a string"` instead of a message that names batching as unsupported (F3, pre-existing).
src/mcp/jsonrpc.rs:56 residual of #6157's headline: a client that only speaks 2025-06-18 or 2026-07-28 still gets `2024-11-05`; 2025-06-18 removed the batch MUST (spec changelog item 1), so its server-side audit (structured content, elicitation, resource links, `title`, `_meta`, Lifecycle SHOULD->MUST) is the next concrete step toward listing a newer revision.
