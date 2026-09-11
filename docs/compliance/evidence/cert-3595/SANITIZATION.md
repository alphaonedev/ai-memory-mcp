<!-- Copyright 2026 AlphaOne LLC / SPDX-License-Identifier: Apache-2.0 -->

# cert-3595 evidence sanitization (2026-09-11 §7 re-validation after #3582)

These files are **recorded artifacts** of the enterprise-federation
certification §7 acceptance battery run on 2026-09-11 against
`ad60beadf602823c4451ff82067f62091aba9a04` (`origin/chain/next` at
lane start: Merge #3593 on Merge #3582). They are **not** regenerated
by CI. Host: f1 macOS; PostgreSQL 18 + AGE + pgvector on `:5445`
(`sslmode=verify-full`); exclusive live database `ai_memory_grok_cert`
(never the operator DB, never `ai_memory_test`).

This recapture is the #3595 unit: boot / signed+nonce'd scoped push /
`{}` deny-all / catchup row+cursor preserve / doctor+capabilities
content-free, on **both** backends. It is **not** a recapture of the
§5.4(2) four-leg `doctor --posture enterprise-federation` sqlcipher
bundle (`cert-55/`); that bundle stays the 20-check posture-leg
evidence of record. #3582 did not add or remove an
`ENTERPRISE_FEDERATION_CHECK_COUNT` row.

## The artifacts

| File | What it records |
|---|---|
| `test-results.txt` | Exact `test result:` lines from each cargo invocation (default features, then `--features sal,sal-postgres`). |
| `named-tests.txt` | Exact `test <name> ... ok` lines for the §7 suites (sqlite + postgres twins). |

## What was sanitized / omitted

- Cargo progress bars, compiler warnings, and absolute `CARGO_TARGET_DIR`
  paths were **not** copied. Only the `test result:` / `test <name>` lines.
- The live DSN (including the postgres role password) was process-env only
  and does **not** appear in these files.
- No API keys, passphrases, PEM blocks, peer IDs from production, or
  operator home paths.

## What was NOT present (and therefore not redacted)

- No `skip:` lines and no `ignored; N` with N>0.
- No `test result: FAILED` lines.
