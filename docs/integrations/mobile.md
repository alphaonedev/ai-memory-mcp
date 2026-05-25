# Mobile artifact signing — consumer-signs-at-app-integration

> **Status — v0.7.0:** ai-memory's iOS xcframework (`ai-memory-ios.xcframework.tar.gz`)
> and Android tar.gz (`ai-memory-android.tar.gz`) ship from the release
> pipeline **unsigned**. Code signing is the **consumer's responsibility**
> at app-integration time — see §"Why consumer-signs-at-integration"
> below for the rationale. Producer-side codesign is a v0.7.x follow-up
> tracked under issue [#1068](https://github.com/alphaonedev/ai-memory-mcp/issues/1068)
> (Posture-1a, Layer 2). This document closes
> [#1247](https://github.com/alphaonedev/ai-memory-mcp/issues/1247).

For the broader mobile / IoT operator guide, see
[`docs/mobile-iot-deployment.md`](../mobile-iot-deployment.md). For the
release pipeline jobs that produce the artifacts, see
[`.github/workflows/release.yml`](../../.github/workflows/release.yml)
(`mobile-ios` + `mobile-android` jobs).

## TL;DR

1. ai-memory at v0.7.0 publishes **unsigned** mobile artifacts.
2. **You** — the iOS / Android app developer integrating the library —
   sign the artifact as part of YOUR app's normal codesign flow with
   YOUR Apple Developer / Google Play certificate.
3. Producer-side signing (an Anthropic-of-AlphaOne–owned certificate
   that pre-signs the artifact at release time) is on the v0.7.x
   roadmap. It is NOT load-bearing — the consumer-side codesign
   below is the contract end-users actually trust.

## What ships in v0.7.0

The `release.yml` workflow produces two mobile artifacts per tag:

| Artifact | Layout | Slices | Signed? |
|---|---|---|---|
| `ai-memory-ios.xcframework.tar.gz` | Apple xcframework | device arm64, simulator arm64, simulator x86_64 | **No** — link-time signing is consumer's job |
| `ai-memory-android.tar.gz` | `jniLibs/<abi>/libai_memory.so` | arm64-v8a, armeabi-v7a, x86_64, x86 | **No** — APK / AAB signing is consumer's job |

Both artifacts pass cross-compile (Layer 1 — `cargo check` per-target
on every PR + push) and runtime tests on the iOS Simulator + Android
emulator (Layer 3 — `mobile-runtime.yml` on `release/**` push). The
gap closed by this document is **Layer 2** signing posture.

## Why consumer-signs-at-integration (rationale)

App-store distribution on both iOS and Android REQUIRES the final
shipped binary to be signed with the **consumer's** distribution
certificate, not the library producer's. Specifically:

- **iOS App Store** rejects an `.ipa` unless every embedded binary
  is signed with a cert in the same provisioning profile as the
  app's main bundle. A producer-side ad-hoc signature would be
  stripped or rejected at archive time by Xcode's `codesign`
  step. App-store policy treats consumer-cert signing as the
  trust anchor, not producer-cert signing.
- **Google Play** requires the entire APK / AAB to be signed with
  the developer's upload key (and re-signed by Play with a Play
  app-signing key for distribution). Pre-signed `.so` files
  embedded in `jniLibs/` are not separately verified at install
  time — the APK signature is the binding contract.

So a producer-side signature on the v0.7.0 artifact would be:
- **Stripped at link time on iOS** (xcframework consumers re-sign).
- **Ignored at install time on Android** (APK signature is what
  the OS checks).

The **operative trust boundary** is consumer-side: the operator who
ships the app to end users is the party whose cert end users have
to trust. Producer-side signing is defense-in-depth above that,
useful for supply-chain attestation (proving the artifact came from
the AlphaOne release pipeline, not a tampered mirror), NOT for the
end-user trust contract.

## Consumer-side signing recipe (iOS)

```bash
# 1. Download + extract the xcframework
curl -L -o ai-memory-ios.xcframework.tar.gz \
  "https://github.com/alphaonedev/ai-memory-mcp/releases/download/v0.7.0/ai-memory-ios.xcframework.tar.gz"
tar -xzf ai-memory-ios.xcframework.tar.gz   # → ./ai-memory.xcframework

# 2. Drop the xcframework into your Xcode project.
#    Targets > <YourApp> > General > Frameworks, Libraries, and Embedded Content.

# 3. Codesign as part of YOUR normal archive build.
#    Xcode's "Embed & Sign" option signs the library with the same
#    cert + entitlements as the parent app. No separate step.

# 4. Verify post-archive (optional but recommended):
codesign -dvv --verbose=4 \
  /path/to/YourApp.app/Frameworks/ai-memory.xcframework/...
```

If you maintain a Swift Package or CocoaPod that wraps ai-memory,
the same logic applies — the **end user's app** signs the embedded
binary at archive time. Your wrapper does NOT need to pre-sign.

## Consumer-side signing recipe (Android)

```bash
# 1. Download + extract the Android bundle
curl -L -o ai-memory-android.tar.gz \
  "https://github.com/alphaonedev/ai-memory-mcp/releases/download/v0.7.0/ai-memory-android.tar.gz"
tar -xzf ai-memory-android.tar.gz   # → ./jniLibs/<abi>/libai_memory.so

# 2. Copy into your Android app module:
cp -r jniLibs app/src/main/

# 3. Build your APK / AAB as normal. The Android Gradle Plugin packs
#    the .so files into the APK, then the APK signing step (v2/v3
#    scheme) signs the entire archive with YOUR upload key.

# 4. Verify post-build:
apksigner verify --verbose app/build/outputs/apk/release/app-release.apk
```

The `.so` files inside `jniLibs/` are not separately verified by
the OS at install time on Android. The APK-level v2/v3 signature
is the binding contract.

## Supply-chain attestation (where producer-side signing fits)

Producer-side codesign is still useful **above** the consumer
contract — it gives downstream integrators a way to verify that
the `.tar.gz` they pulled really came from the AlphaOne release
pipeline and was not tampered with on a mirror. The v0.7.x
follow-up under #1068 adds:

- **iOS**: producer-cert codesign on each xcframework slice +
  notarisation-equivalent attestation manifest (since we are not
  publishing through the App Store, Apple notarisation does not
  apply — the attestation lives in the GitHub release).
- **Android**: producer-cert sign of the `jniLibs/<abi>/*.so` files
  via `apksigner --apk` on a stub APK + detached signature
  publishing alongside the `.tar.gz` in the GitHub release.
- **Both**: SLSA Level 3 provenance attestation generated by the
  release workflow (`actions/attest-build-provenance`) so a
  downstream operator can mechanically verify "this artifact came
  from `release.yml` running on tag `v0.7.x`".

None of those are end-user trust anchors — the consumer-side
codesign in §"Consumer-side signing recipe" remains the binding
contract. They are supply-chain hardening for the integrator.

## Verifying the unsigned v0.7.0 artifact

Pending the producer-cert codesign in v0.7.x, integrators can
verify artifact integrity TODAY using:

1. **GitHub release page checksum manifest** — the `release.yml`
   workflow publishes a `SHA256SUMS.txt` alongside the artifacts.
   Verify with:

   ```bash
   curl -L -o SHA256SUMS.txt \
     "https://github.com/alphaonedev/ai-memory-mcp/releases/download/v0.7.0/SHA256SUMS.txt"
   sha256sum -c SHA256SUMS.txt --ignore-missing
   ```

2. **GitHub release-tarball signature** — GitHub itself signs
   release tarballs with its own infrastructure key. The release
   page UI confirms the signing chain.

3. **Build-from-source** — the entire pipeline is open. If you
   have any doubt about the published binaries, build the
   xcframework / android tarball yourself from the tag:

   ```bash
   git clone https://github.com/alphaonedev/ai-memory-mcp.git
   cd ai-memory-mcp
   git checkout v0.7.0
   # Then mirror the steps in .github/workflows/release.yml
   # under the mobile-ios + mobile-android jobs.
   ```

## Status tracking

- Closes [#1247](https://github.com/alphaonedev/ai-memory-mcp/issues/1247) — documents
  the consumer-signs-at-app-integration expectation for v0.7.0.
- Producer-side codesign follow-up: [#1068](https://github.com/alphaonedev/ai-memory-mcp/issues/1068)
  Layer 2.
- Build pipeline source: [`.github/workflows/release.yml`](../../.github/workflows/release.yml)
  (`mobile-ios` + `mobile-android` jobs).
- Operator guide for running ai-memory on a phone / IoT device:
  [`docs/mobile-iot-deployment.md`](../mobile-iot-deployment.md).
