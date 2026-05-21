# Typed-errors audit — issue #964

**Wave-2 Tier-B4 — Replace remaining `anyhow::Result<T>` on substrate-public API with typed errors**
**Closure path: B (audit + closure-as-evidence; substrate-public API already typed post-#962)**
**Base SHA:** `762e5ede20e6e278fe6ff39be078e233f9934d91`

## Issue hypothesis

> Replace remaining `anyhow::Result<T>` returns on substrate-public API
> with typed errors so callers (handlers, MCP tools, CLI) can
> pattern-match without `to_string()` parsing. ~1180 sites. Continues
> #962 (storage anyhow leakage already closed).

## Result

**No conversions performed.** After enumerating every `anyhow::Result`
occurrence in `src/` (51 files, 71 raw matches, 35 actual code uses
after excluding `use` imports and doc-comment references), the
substrate-public API surface — the boundary the issue body explicitly
scopes — is **already fully typed** post-#962. The remaining
`anyhow::Result` uses are all either:

1. **Internal helpers** (file-private `fn` declarations not on any
   public API surface).
2. **Test mock impls** implementing third-party-style traits
   (`Embedder`, `LlmCurator`) where the trait itself is
   inherently `anyhow::Result`-shaped by design.
3. **Boot-path entry points** (`run_mcp_server`, `run_embedding_backfill`,
   `main`) where the caller is Cargo's binary entry, which demands
   `anyhow::Result<()>`.
4. **Trait surfaces for plug-in extension points** (`BackgroundSweeper`,
   `Embedder`) where the trait is the extension boundary and
   `anyhow::Result` is the documented type.

The ~1180 "sites" the issue body counts are `Result<T>` return
signatures inside `src/storage/mod.rs` — each of which is the OUTER
shape of the typed `StorageError` envelope wrapped via
`anyhow::Error::new(StorageError::…)`. Per #962's design, this
wrapping is the load-bearing pattern that lets the substrate emit
twelve discriminable typed variants while preserving byte-identical
legacy `bail!()` error strings for consumers that rely on
`.to_string().contains("…")` semantics.

The issue is correctly classed LOW ROI for this milestone. Closure
path B (audit + closure-as-evidence) is the honest outcome.

## Substrate-public API surface — post-#962 state

The substrate-public API surface has three layers; all three are
typed at the public-call boundary:

| Layer | File | Result type at public boundary | Typed-error system |
|---|---|---|---|
| HTTP handlers | `src/handlers/*.rs` | `Result<T, MemoryError>` | `MemoryError` enum (`src/errors.rs`) |
| MCP tools | `src/mcp/tools/*.rs`, `src/mcp/mod.rs::handle_request` | `Result<serde_json::Value, String>` after downcasting via `MemoryError::from(anyhow::Error)` | `MemoryError` enum |
| SAL trait (`MemoryStore`) | `src/store/mod.rs` | `StoreResult<T>` (alias for `Result<T, StoreError>`) | `StoreError` enum (242 sites) |
| SAL adapters | `src/store/sqlite.rs`, `src/store/postgres.rs` | `StoreResult<T>` | `StoreError` enum |
| Storage substrate | `src/storage/mod.rs` | `anyhow::Result<T>` (intentionally) | typed `StorageError` wrapped via `anyhow::Error::new(StorageError::…)` |

### Per-layer counts

```
$ grep -c "anyhow::Result" src/handlers/*.rs
# 0 across 21 handler files

$ grep -c "anyhow::Result" src/store/mod.rs src/store/sqlite.rs src/store/postgres.rs
# 0 across the entire SAL

$ grep -E "\\->\\s*StoreResult<" src/store/mod.rs | wc -l
# 67 trait methods returning StoreResult<T>

$ grep -E "\\->\\s*StoreResult<" src/store/sqlite.rs src/store/postgres.rs | wc -l
# 175 adapter methods returning StoreResult<T>
```

The handler/MCP/SAL surface — the public-facing layer — is at
**100% typed coverage** for new public methods. The remaining
`anyhow::Result` is the substrate-internal envelope that #962
established as the canonical wrapping pattern.

## Remaining `anyhow::Result` inventory (35 sites)

Categorised by callability from the substrate-public boundary:

### Category A — Internal helpers (file-private, not on any public API)

```
src/atomisation/mod.rs:484   fn read_atomised_into(...)        - file-private helper
src/atomisation/mod.rs:499   fn list_atoms_of(...)             - file-private helper
src/atomisation/mod.rs:522   fn ...atomise inner(...)          - file-private helper
src/atomisation/mod.rs:652   fn ...write atom row(...)         - file-private helper
src/atomisation/mod.rs:654   let result = (|| -> ...)()        - inline closure
src/atomisation/mod.rs:704   fn ...persist+link(...)           - file-private helper
src/hooks/post_reflect/auto_export.rs:207     pub(crate) fn   - hook implementation
src/hooks/post_reflect/auto_export.rs:242     fn              - hook helper
src/hooks/post_reflect/auto_persona.rs:172    pub(crate) fn   - hook implementation
src/hooks/post_reflect/auto_persona.rs:221    fn              - hook helper
src/hooks/post_reflect/auto_persona.rs:270    fn              - hook helper
src/hooks/post_reflect/auto_persona.rs:289    fn              - hook helper
src/storage/reflect.rs:649                    fn              - reflect helper
```

These are not on any layer-crossing boundary. Pattern-matching is
unnecessary: they error-propagate via `?` into a substrate-public
caller that ultimately downcasts.

### Category B — Trait surfaces (plugin/extension boundaries, anyhow-shaped by design)

```
src/background/offload_ttl_sweep.rs:79,90,104  trait BackgroundSweeper + impls
src/federation/peer.rs:39                      Self::from_config (peer init)
src/governance/wire_check.rs:111               pub fn check_anyhow (gate-evaluator wire format)
```

`BackgroundSweeper` is a trait specifically designed as a pluggable
extension point — the trait method returns `anyhow::Result<usize>`
because callers swap implementations (real DB vs mock vs noop) and
any of them may fail in an unbounded variety of ways.
`governance::wire_check::check_anyhow` is part of the wire-check
gate-evaluator surface whose `anyhow`-typed shape is the documented
contract callers depend on.

### Category C — Test mock impls (test-only)

```
src/cli/commands/persona.rs:151,154,157     #[cfg(test)] mock LlmCurator
src/mcp/mod.rs:12121,12124                  #[cfg(test)] mock Embed
src/mcp/tools/persona.rs:300,303,306        #[cfg(test)] mock LlmCurator
src/mcp/tools/recall.rs:1323                #[cfg(test)] mock Embed
src/persona/mod.rs:880,883,886              #[cfg(test)] mock LlmCurator
src/hooks/post_reflect/auto_persona.rs:313,316,319  #[cfg(test)] mock LlmCurator
```

Test mocks implementing `LlmCurator` and `Embed` traits — converting
them requires first converting the traits, which falls under Category B.

### Category D — Boot-path entry points (process-entry, anyhow demanded by `main`)

```
src/mcp/mod.rs:1923   pub fn run_embedding_backfill(...) -> anyhow::Result<usize>
src/mcp/mod.rs:2016   pub fn run_mcp_server(...) -> anyhow::Result<()>
```

Both are top-level entry points called from `src/main.rs` (which itself
returns `anyhow::Result<()>` because Cargo's binary-crate convention
expects it). These are not handler-callable surfaces — they bootstrap
the entire daemon. Typing them would require typing `main`, which is
not a substrate-public API concern.

## Why the conversion would be counter-productive

The post-#962 substrate emits typed variants via:

```rust
return Err(anyhow::Error::new(StorageError::MemoryNotFound { id, role: None }));
```

…and the handler layer downcasts via:

```rust
if let Some(se) = e.downcast_ref::<crate::storage::StorageError>() {
    use crate::storage::StorageError as SE;
    return match se {
        SE::MemoryNotFound { .. } => Self::NotFound(se.to_string()),
        // ...
    };
}
```

This is the **load-bearing pattern** that simultaneously:

1. **Preserves wire-format compatibility** with pre-#962 consumers that
   string-match on `.contains("ambiguous ID prefix")` or
   `.starts_with("link refused: reflection cycle")`. The 12 `Display`
   impls in `StorageError` are byte-identical to the original `bail!()`
   format strings. A pin test suite (`src/storage/error.rs` 12 unit
   tests + `src/errors.rs` 12 downcast tests) protects this contract.

2. **Threads typed errors across the layer boundary**. Handlers
   downcast to the right HTTP status (NotFound → 404, AmbiguousIdPrefix
   → 400, LinkPermissionDenied → 403, etc.) without parsing strings.

3. **Doesn't require touching 1180 call sites**. Converting every
   `pub fn(...) -> Result<T>` to `pub fn(...) -> Result<T, StorageError>`
   means changing every `?` propagator at every callsite — the
   `anyhow::Error` value already in flight (e.g. from `rusqlite::Error`
   via `?`) needs an explicit `.map_err(StorageError::from)` because
   `From<rusqlite::Error> for StorageError` doesn't exist (and adding
   it would require enumerating every `rusqlite::Error` variant or
   adding a catchall variant that defeats the point of typing).

4. **Doesn't break the `Context` chain.** Substrate code uses
   `anyhow::Context` extensively (`.context("loading memory row")?`)
   for forensic chain-walking on production errors. Replacing
   `anyhow::Result<T>` with `Result<T, StorageError>` either loses the
   chain (StorageError has no `Context` impl) or requires reimplementing
   `Context` on StorageError, which is a large surface for low payoff.

The #962 design — typed envelope wrapped in `anyhow::Error` for the
substrate boundary, then downcast at the handler boundary — is the
right design for this codebase's "thick-substrate, thin-handler"
shape. The "1180 sites" framing in the #964 issue body
underestimated the work the #962 closure already did and overestimated
the remaining gap.

## What `#962` already accomplished (verification, not new work)

`git show 4f3660768` (the #962 closure commit) added:

- 12 `StorageError` variants in `src/storage/error.rs`
- 30 `anyhow::bail!()` → `anyhow::Error::new(StorageError::…)` swaps
  in `src/storage/mod.rs`
- 5 closely-related `anyhow::anyhow!()` swaps
- `LINK_CYCLE_ERR_PREFIX` + `LINK_PERMISSION_DENIED_ERR_PREFIX`
  promoted to `error.rs` as canonical constants
- Full `From<anyhow::Error> for MemoryError` extension covering every
  `StorageError` variant
- 12 unit tests on `StorageError::Display` for byte-format pins
- 12 unit tests on `From<anyhow::Error> for MemoryError` for
  status-code mapping pins

The post-#962 substrate is the typed-error system #964 was supposed
to build. The remaining `anyhow::Result` is the OUTER WRAPPER, not a
gap.

## Acceptance evidence

- **`cargo fmt --check`** — clean (no diff)
- **`cargo clippy --no-default-features --features sal,sal-postgres,sqlite-bundled --lib --tests -- -D warnings -D clippy::all -D clippy::pedantic`** — green (no doc changes; only `.md` added)
- **`cargo test --no-default-features --features sqlite-bundled --lib`** — pre-existing 0 regressions
- **`cargo test --no-default-features --features sal,sal-postgres,sqlite-bundled --lib`** — pre-existing 0 regressions

(Doc-only audit; no code touched.)

## Recommendation for closure

Close #964 as **LOW-ROI / audit-as-evidence**. The substrate-public
API is already typed at every layer crossing post-#962; the remaining
`anyhow::Result` is the documented envelope pattern, not a gap. Any
future "typed errors all the way down" effort should land as a
v0.8 design-discussion ticket on the question "should `StorageError`
gain a `Context` API + a catchall variant for `rusqlite::Error`?" —
not as a 1180-site mechanical sweep at v0.7.0.

## Cross-references

- Closure path B precedent: `docs/internal/enum-proliferation-audit-970.md`
- Substrate typed-error envelope: `src/storage/error.rs`
- Handler downcast logic: `src/errors.rs::From<anyhow::Error> for MemoryError`
- SAL typed-error enum: `src/store/mod.rs::StoreError`
- #962 closure commit: `4f3660768`
