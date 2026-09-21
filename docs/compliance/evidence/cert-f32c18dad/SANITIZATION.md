<!-- Copyright 2026 AlphaOne LLC / SPDX-License-Identifier: Apache-2.0 -->

# cert-f32c18dad evidence sanitization (2026-09-21 re-issue after 12 §7-watched federation-wire files changed since `ab6f2175`)

These files are **recorded artifacts** of the enterprise-federation
certification re-issue run on 2026-09-21 against the v1.0.0 promotion-candidate
tip `f32c18dadf8a659567960747cc2802186bac9de9`. They are **not** regenerated
by CI. Host: a Linux build host; release-built binaries of this exact tip (one
default / non-sqlcipher, one `--no-default-features --features sqlcipher,sal`)
for the four §5.4(2) posture legs; the §5.4(4)/(7) acceptance battery run under
default features on the same tip. The §5.4(3) Postgres+AGE tier and the live-pg
§5.4(4) negative lanes are cited from CI on this SHA (see the cert §7 record),
not re-run on the host.

## The artifacts

| File | What it records |
|---|---|
| `posture-bare-env.out` | Bare env (`AI_MEMORY_NO_CONFIG=1`, nothing set): exit 2, **10 `[FAIL]` / 12 `[PASS]` of 22**. |
| `posture-hardened-env.out` | Hardened env WITHOUT sqlcipher and WITHOUT the boot gate armed: exit 2, **2 `[FAIL]` / 20 `[PASS]`** (`AI_MEMORY_ENCRYPT_AT_REST`, `AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE`). |
| `posture-hardened-boot-refusal.out` | The SAME hardened non-sqlcipher env WITH `AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE=1`: the binary **refuses to boot** (exit 1), naming the below-floor control. |
| `posture-sqlcipher-pass.out` | The certified configuration (`--features sqlcipher`, `AI_MEMORY_ENCRYPT_AT_REST=1`, boot gate ARMED, `AI_MEMORY_DB_SYNCHRONOUS=FULL`, operator key pair): exit 0, **22 `[PASS]` / 0 `[FAIL]`**. |
| `posture-legs-exit-codes.txt` | The four recorded shell exit statuses (2 / 2 / 1 / 0). |
| `test-results.txt` | Exact `test result:` lines: the eight named §5.4(4)/(7) integration binaries, then the three lib-slice filters run as SEPARATE invocations (`enterprise_federation_posture` 38, `federation::peer_posture` 5, `cli::backup::tests` 81; all 0 failed). |
| `peer-fingerprints.txt`, `peer-attestation.json` | The throwaway fixture peer map used by the hardened legs (placeholder fingerprint, placeholder peer). |
| `MANIFEST.sha256` | sha256 of every file above. |

## What was sanitized / omitted

- Cargo progress bars, compiler warnings, and absolute `CARGO_TARGET_DIR` /
  fixture / `$HOME` paths were collapsed to `<repo-root>` / `<home>` by the
  recapture script's `sanitize` pass.
- The fixture peer map is placeholder data (a single non-routable peer with a
  1111… fingerprint); it contains no real fleet identities.
- No operator, shared, or production database was touched; the sqlcipher leg
  used an exclusive throwaway encrypted fixture store.

## Reproduce

`scripts/recapture-cert-f32c-posture.sh` regenerates the four posture legs
(point `DEFAULT_BIN` / `SQLCIPHER_BIN` at release builds of `f32c18dad`); the
acceptance battery is `cargo test --test <name>` for the eight named binaries
and three SEPARATE `cargo test --lib <filter>` invocations (never one
invocation with three positionals — cargo refuses that before any test runs).
