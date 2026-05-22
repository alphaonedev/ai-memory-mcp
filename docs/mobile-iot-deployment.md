# ai-memory on phones, IoT, and the edge

> **Status — v0.7.0 (2026-05-22):** the build pipeline (cross-compile +
> mobile artifact bundling + iOS Simulator + Android emulator runtime
> tests) ships and stays green on every `release/**` push. The
> C-callable FFI surface — `#[no_mangle] extern "C"` items in
> `src/lib.rs` — lands in a v0.7.x follow-up (issue #1068 Layer 2).
> The artifacts produced today (`ai-memory-ios.xcframework.tar.gz`,
> `ai-memory-android.tar.gz`) are LINKABLE — embed them in an Xcode
> or Android Studio project and link against the bundled rlib /
> staticlib / cdylib — but the public FFI surface is a stub header
> (`cbindgen.toml`) until Layer 2 declares it. Native CLI use over
> Termux (Android) or a sidecar Mac (iOS) is supported TODAY.

This document is the operator guide for running ai-memory off a
laptop / server — on a phone in your pocket, on a Raspberry Pi in a
greenhouse, on a Cortex-A72-class drone payload computer, on an
automotive head-unit, on a wearable. The substrate is small enough,
fast enough, and portable enough that "AI with persistent memory on a
phone" is no longer a research aspiration; it is a deployment target
ai-memory has CI gates for.

For the laptop / server install path, see
[`docs/install-quickstart.md`](install-quickstart.md). For the
mobile-runtime CI matrix, see
[`.github/workflows/mobile-runtime.yml`](../.github/workflows/mobile-runtime.yml).
For the reference architectures (which include a mobile-edge tier),
see [`docs/reference-architectures.md`](reference-architectures.md).

## 1. Why this matters

The vast majority of "AI on edge devices" work today carries a
hidden tax: the AI agent has no persistent memory. Every session
starts cold. Every preference, every learned correction, every
conversational habit gets re-elicited from scratch — or it lives in
a cloud service that the device has to round-trip to.

ai-memory inverts that:

- **~31 MB statically-linked release binary** (post strip + thin
  LTO; `cargo build --release` produces it). That is small enough
  to ship in an app bundle, small enough to flash to an SD card,
  small enough to airdrop to an embedded device over a serial
  link. By comparison, a stock Postgres binary + libpq is ~70 MB
  before you count the data dir.
- **Single-file SQLite database**, WAL mode, FTS5 + HNSW + Form-4
  vector storage in one `.db` file. Copy the file off → you have
  the full memory state. No service discovery, no schema
  migrations on the device side, no daemon-to-daemon handshake.
- **Architectures**: ARM64 (Apple Silicon, Raspberry Pi 4/5,
  Snapdragon, MediaTek, NVIDIA Jetson, every modern phone),
  x86_64 (Intel / AMD laptops, NUCs, x86 industrial PCs), and
  RISC-V (BeagleV, VisionFive 2, SiFive — buildable today from
  source, prebuilt artifacts on the v0.7.x roadmap).
- **Operating systems**: macOS, Linux, Android, iOS, FreeBSD,
  Windows (via WSL on the desktop; native MSVC build at
  `release.yml`'s `x86_64-pc-windows-msvc` job), and any
  POSIX-ish system that can host a static-linked Rust binary.
- **No phone-home, no telemetry, no outbound calls** unless the
  operator opts into federation or a hosted LLM provider. Plays
  cleanly on devices that may be air-gapped, intermittently
  connected, or behind carrier NAT.

For mobile AI assistants, IoT endpoints, drones, wearables, and
field sensors, that combination — small binary + single-file DB +
ARM-native + no phone-home — is a step change. The AI on the
device gets a memory that survives reboot, survives app uninstall
(if backed up), survives airplane mode, and can sync up to a
regional hub on its own schedule.

## 2. Supported targets

The canonical CI matrix is in
[`.github/workflows/release.yml`](../.github/workflows/release.yml)
(prebuilt artifacts) and
[`.github/workflows/mobile-runtime.yml`](../.github/workflows/mobile-runtime.yml)
(runtime gating on simulators / emulators).

| Class | OS | Architecture | Target triple | v0.7.0 status |
|---|---|---|---|---|
| Desktop | macOS | aarch64 (Apple Silicon) | `aarch64-apple-darwin` | Prebuilt binary on every release |
| Desktop | macOS | x86_64 (Intel) | `x86_64-apple-darwin` | Prebuilt binary on every release |
| Desktop | Linux | x86_64 | `x86_64-unknown-linux-gnu` | Prebuilt binary on every release |
| Desktop | Linux | aarch64 (server / Pi / Graviton) | `aarch64-unknown-linux-gnu` | Prebuilt binary on every release |
| Desktop | Windows | x86_64 | `x86_64-pc-windows-msvc` | Prebuilt binary on every release |
| Phone | iOS | aarch64 device | `aarch64-apple-ios` | Build pipeline GREEN; linkable staticlib in `.xcframework.tar.gz`. FFI items: v0.7.x follow-up. |
| Phone | iOS Simulator | aarch64 (Apple Silicon Mac) | `aarch64-apple-ios-sim` | Build + runtime test GREEN (mobile-runtime workflow) |
| Phone | iOS Simulator | x86_64 (Intel Mac) | `x86_64-apple-ios` | Build pipeline GREEN; Intel runner image is on its EOL path so runtime arm not run in CI |
| Phone | Android | aarch64 (`arm64-v8a`) | `aarch64-linux-android` | Build pipeline GREEN; cdylib bundled in `.aar`-compatible archive |
| Phone | Android | armv7 (`armeabi-v7a`) | `armv7-linux-androideabi` | Build pipeline GREEN; cdylib bundled (older devices, ~5%) |
| Phone | Android | x86_64 (emulator) | `x86_64-linux-android` | Build + runtime test GREEN on KVM-accelerated emulator |
| Phone | Android | i686 (legacy emulator) | `i686-linux-android` | Build pipeline GREEN |
| IoT | Linux | aarch64 (Pi 4 / 5, Rock 5, Jetson Nano / Orin Nano) | `aarch64-unknown-linux-gnu` | Same prebuilt as desktop Linux ARM64 |
| IoT | Linux | armv7 (Pi Zero 2 W, older Pi) | `armv7-unknown-linux-gnueabihf` | Build-from-source today; prebuilt on the v0.7.x roadmap |
| IoT | Linux | riscv64 (VisionFive 2, BeagleV) | `riscv64gc-unknown-linux-gnu` | Build-from-source today; no prebuilt artifact |
| Embedded | FreeBSD | x86_64 / aarch64 | `x86_64-unknown-freebsd` / `aarch64-unknown-freebsd` | Build-from-source; community-attested but not gated by upstream CI |

The lib target's `crate-type = ["rlib", "staticlib", "cdylib"]`
(see [`Cargo.toml`](../Cargo.toml) line 447) is what makes the
mobile slices possible: `staticlib` produces `libai_memory.a`
that the iOS xcframework wraps, `cdylib` produces
`libai_memory.so` that the Android `.aar` ships under
`jniLibs/<abi>/`.

The default `cargo build --release --features sqlite-bundled`
on Android uses **rustls-only** TLS — no `openssl-sys` in the
transitive graph — so the Android NDK build does not need
libssl. The `Pin no-openssl-sys invariant (#1070)` step in
`mobile-runtime.yml` enforces this on every push.

## 3. Cellphone: Android (Termux)

This is the path that works **today**, without waiting for the
FFI surface to ship. Termux gives you a real userland on Android
with package management, a shell, and an executable bit on the
file system.

### Install

```bash
# In Termux (F-Droid build recommended — Play Store build is on
# old packages):
pkg update && pkg upgrade
pkg install rust git clang make

# Build from source. The Android NDK isn't needed when you build
# IN Termux — you're building for the native arch already.
cd ~ && git clone https://github.com/alphaonedev/ai-memory-mcp.git
cd ai-memory-mcp
cargo build --release --no-default-features --features sqlite-bundled

# Install
cp target/release/ai-memory $PREFIX/bin/
ai-memory --version
```

Build time on a modern phone (Pixel 8 Pro, S24, etc.) is ~6–10
minutes. On a 2020-era mid-range phone, expect 15–25 minutes.

### Run as a user service

Termux supports user services via `termux-services`:

```bash
pkg install termux-services
mkdir -p $PREFIX/var/service/ai-memory
cat > $PREFIX/var/service/ai-memory/run <<'SH'
#!/data/data/com.termux/files/usr/bin/sh
exec ai-memory serve \
  --db $HOME/.ai-memory/ai-memory.db \
  --bind 127.0.0.1:9077
SH
chmod +x $PREFIX/var/service/ai-memory/run
sv-enable ai-memory
sv up ai-memory
```

Now any Termux-hosted AI client on the phone (Ollama-on-Termux,
llama.cpp server, an MCP-speaking app shelled over `adb`, etc.)
can hit `http://127.0.0.1:9077/api/v1/` for memory persistence.

### Battery hygiene

- Disable Android's aggressive power-save for Termux: Settings →
  Apps → Termux → Battery → "Unrestricted". Without this, the
  daemon gets SIGSTOPped after the screen has been off for ~30 min.
- Set `--gc-interval 3600` (1h) instead of the default 30 min on a
  battery-powered phone — GC sweeps wake the radio if the schema
  triggers any audit-chain emit on rotation.

## 4. Cellphone: iOS

iOS is the harder of the two. App Store policy prohibits a
user-installable CLI; iOS apps run in a sandbox; there is no
"Termux for iOS." The honest state at v0.7.0:

### What works today

- **Build pipeline is green.** Every release publishes
  `ai-memory-ios.xcframework.tar.gz` containing three slices
  (device arm64, Simulator arm64, Simulator x86_64), linkable
  into an Xcode project.
- **Runtime tests are green on the iOS Simulator** (the
  `mobile-runtime.yml` `ios-simulator` job validates SQLite + WAL,
  HNSW CPU recall, embedder CPU path, and rustls TLS handshake
  every push to `release/**`).
- **Embed-via-staticlib** is supported: drop the xcframework into
  your Xcode project, link, and call the (forthcoming) `extern "C"`
  surface from Swift / Objective-C.

### What does not work today

- **No public C-FFI surface yet.** The `cbindgen.toml` generates a
  stub header — there are no `#[no_mangle] extern "C"` items in
  `src/lib.rs` at v0.7.0. So while the staticlib bundles
  correctly, you cannot meaningfully call into it from Swift
  until v0.7.x ships the items (issue #1068 Layer 2). The
  build-pipeline-without-callable-surface scaffold is intentional;
  it pins the artifact + signing + xcframework layout before any
  API churn.
- **No stand-alone iOS app on the App Store.** Apple's review
  guidelines and the lack of background-daemon support make a
  standalone "ai-memory.app" a poor fit. The intended model is:
  your AI app embeds the xcframework + calls into it through
  the FFI when v0.7.x ships.

### The pragmatic path today

Run ai-memory on a **Mac sidecar** on the same Wi-Fi as the iPhone /
iPad:

```bash
# On a Mac on the same network:
ai-memory serve --bind 0.0.0.0:9077 --db ~/Documents/family-memory.db

# In your iOS app, point your MCP / HTTP client at:
# http://<mac-lan-ip>:9077/api/v1/
```

This is the **bring-your-own-Mac** posture. The iPhone gets
persistent memory by talking to the Mac in your house / car / bag
over LAN. It's not phone-native, but it's deployable today, and
the latency is sub-10ms over local Wi-Fi.

A v0.7.x follow-up ("phone-native" posture) lands the FFI surface
and unlocks in-app embedded use. Tracking: issue #1068 Layer 2.

## 5. IoT: Raspberry Pi 4/5 and Linux ARM SBCs

This is the **best-supported** edge target at v0.7.0. The
prebuilt `aarch64-unknown-linux-gnu` binary works on:

- Raspberry Pi 4 / 5 (Pi OS 64-bit)
- Rock 5A / 5B / 5C (Armbian, Debian)
- Orange Pi 5 / 5 Plus
- BananaPi M5 / M7
- NVIDIA Jetson Nano / Orin Nano (L4T)
- AWS Graviton instances (same triple, server-side)
- Apple Silicon Mac (server-side)

### Install

```bash
# On the Pi (or any aarch64 Linux):
curl -fsSL https://github.com/alphaonedev/ai-memory-mcp/releases/download/v0.7.0/ai-memory-aarch64-unknown-linux-gnu.tar.gz \
  | sudo tar -xz -C /usr/local/bin --strip-components=1 ai-memory/ai-memory
ai-memory --version
```

That's it — the prebuilt aarch64 binary is self-contained.

### systemd unit

Drop this at `/etc/systemd/system/ai-memory.service`:

```ini
[Unit]
Description=ai-memory persistent memory daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ai-memory
Group=ai-memory
ExecStart=/usr/local/bin/ai-memory serve \
  --db /var/lib/ai-memory/ai-memory.db \
  --bind 127.0.0.1:9077 \
  --log-dir /var/log/ai-memory
Restart=on-failure
RestartSec=5
# Resource caps — sane defaults for a Pi 4 (4GB) / Pi 5 (8GB):
MemoryMax=512M
CPUQuota=80%
# Hardening:
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ai-memory /var/log/ai-memory

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo useradd --system --home /var/lib/ai-memory ai-memory
sudo mkdir -p /var/lib/ai-memory /var/log/ai-memory
sudo chown ai-memory:ai-memory /var/lib/ai-memory /var/log/ai-memory
sudo systemctl daemon-reload
sudo systemctl enable --now ai-memory
sudo systemctl status ai-memory
```

### Cross-compile from a development host

If you want to push fresh builds to a Pi without compiling on
the Pi (which is slow — ~15 min release build on a Pi 4):

```bash
# On your laptop:
rustup target add aarch64-unknown-linux-gnu
sudo apt install -y gcc-aarch64-linux-gnu        # Debian/Ubuntu
brew install aarch64-elf-gcc                     # macOS
cargo build --release --target aarch64-unknown-linux-gnu \
  --no-default-features --features sqlite-bundled
scp target/aarch64-unknown-linux-gnu/release/ai-memory pi@pi.local:/tmp/
ssh pi@pi.local "sudo mv /tmp/ai-memory /usr/local/bin/ && sudo systemctl restart ai-memory"
```

## 6. IoT: ARM Cortex-A72-class boards — resource budget

A Cortex-A72-class quad-core (Pi 4, Rock 5A, Jetson Nano) at 1.5–
1.8 GHz is the **bottom of the comfortable performance band**.
Below that — single-core A53, Cortex-M-class MCUs — ai-memory will
build and run but recall latency starts to dominate.

| Resource | Cortex-A72 quad-core, 4 GB RAM, eMMC | Notes |
|---|---|---|
| Binary size | ~31 MB | Same as desktop; cross-compile output is stripped + thin-LTO |
| RAM at rest (daemon idle) | ~18–25 MB RSS | sqlite + HNSW empty + tracing subscriber |
| RAM under recall load | ~80–120 MB RSS | HNSW resident for 10k vectors at default dim=384 |
| RAM under embedding load | +250–400 MB | MiniLM CPU inference; turn off by running `--profile keyword` if RAM-constrained |
| CPU recall p95 (FTS5 only, `--profile keyword`) | ~3 ms | 10k-row corpus |
| CPU recall p95 (FTS5 + HNSW, `--profile semantic`) | ~25–40 ms | 10k-row corpus, 384-dim embeddings |
| Disk per 1k memories | ~6 MB | Includes FTS5 index, vector embeddings, audit chain |
| Disk per 10k memories | ~55 MB | Includes archive table, expired memory backfill |
| Disk per 100k memories | ~520 MB | HNSW graph contributes ~120 MB at this scale |
| Disk per 1M memories | ~5.0 GB | Strongly recommend external SSD on USB 3 / NVMe-on-PCIe rather than eMMC at this scale |

For 1M+ memories on a Pi-class device, use the `--store-url
postgres://...` SAL path to push the heavy storage off-device to
a Postgres+AGE node on the same LAN (see
[`docs/reference-architectures.md`](reference-architectures.md)
topology 9 — mobile-edge tier).

## 7. IoT: RISC-V

RISC-V is the frontier target. At v0.7.0:

- **No prebuilt artifact.** Compile from source on the target.
- **Native build works** on `riscv64gc-unknown-linux-gnu`
  (VisionFive 2 with the latest Debian, BeagleV-Ahead with the
  Ubuntu 24.04 image, SiFive HiFive Unmatched with Fedora
  RISC-V).
- **No upstream CI gate yet.** Tracking under "expand mobile-
  runtime CI to RISC-V Linux" on the v0.7.x roadmap. Until the
  CI gate ships, RISC-V is community-attested but not
  upstream-warranted.

### Build instructions

```bash
# On the RISC-V board, Debian/Ubuntu:
sudo apt install -y rustc cargo libsqlite3-dev pkg-config
git clone https://github.com/alphaonedev/ai-memory-mcp.git
cd ai-memory-mcp
cargo build --release --no-default-features --features sqlite-bundled

# Binary at target/release/ai-memory
sudo cp target/release/ai-memory /usr/local/bin/
ai-memory --version
```

Build time on a VisionFive 2 (StarFive JH7110, 4× SiFive U74 at
1.5 GHz, 8 GB DDR4) is ~30–45 minutes for a release build —
slower than ARM, because the compiler ecosystem is younger and
codegen for RISC-V Vector extensions is still landing in LLVM.

A v0.7.x release will add `riscv64gc-unknown-linux-gnu` to the
prebuilt-artifact matrix in `release.yml`. Until then,
build-from-source is the only supported path.

## 8. Resource envelope (reference numbers)

The numbers below are measured on a release build, sqlite-bundled,
`--profile semantic`, MiniLM-L6-v2 384-dim embeddings, on a
benchmark host running ai-memory's own `cargo bench --bench
recall` after a representative seed corpus. Use them to size
provisioning for a fleet.

| Memories | Disk (.db) | HNSW resident RAM | FTS5 index RAM | Total RSS at recall p95 | Recall p95 (cold) | Recall p95 (warm) |
|---|---|---|---|---|---|---|
| 1,000 | ~6 MB | ~5 MB | ~1 MB | ~70 MB | ~8 ms | ~3 ms |
| 10,000 | ~55 MB | ~32 MB | ~6 MB | ~120 MB | ~22 ms | ~12 ms |
| 100,000 | ~520 MB | ~220 MB | ~38 MB | ~430 MB | ~85 ms | ~45 ms |
| 1,000,000 | ~5.0 GB | ~1.8 GB | ~310 MB | ~2.4 GB | ~280 ms | ~140 ms |

**Numbers above are on a Cortex-A76 / M2 / Ryzen 7 class host.**
Cortex-A72 / Cortex-A53 boards see 1.5–2.5× higher latency at the
same corpus size. The HNSW + embedder path is CPU-bound; recall
latency scales roughly with single-core performance up to the
HNSW saturation point (typically 100k+ vectors).

**Battery on a phone**: on a Pixel 8 Pro running ai-memory in
Termux, an idle daemon (`serve` with no traffic) consumes ~0.4%
battery / hour. Under continuous recall load (~10 req/s), it
consumes ~3.5% / hour. The phone radio dominates total power; the
ai-memory daemon itself is a small fraction.

## 9. Battery considerations

ai-memory has two run modes that matter for battery:

### Daemon mode (`ai-memory serve`)

The HTTP daemon stays resident, serves requests with sub-ms wakeup
latency, keeps the SQLite connection + HNSW + FTS5 caches hot. Best
for: AI assistants that hit the substrate often (every few seconds
during an active conversation), interactive use, IoT sensors that
push memory rows continuously.

Tuning knobs that matter on battery:

- `--gc-interval` — default 30 min. Raise to 1–4h on battery
  devices to reduce wake-the-CPU overhead.
- `--checkpoint-interval` — default 5 min. Raise to 15–30 min to
  reduce write-wakeups (WAL checkpointing is the largest
  background CPU cost).
- `--profile keyword` — disables the embedder + reranker. Cuts
  recall RAM by ~250 MB and recall CPU by ~80%, at the cost of
  the semantic blend. Good default for low-power IoT sensors that
  only ever do tag / FTS5 lookups.

### Ephemeral mode (CLI invocation per call)

```bash
ai-memory recall "what did the user say about pizza"
```

Each invocation pays the binary-startup cost (~80–120 ms cold) but
consumes zero battery between calls. Best for: cron-driven sensors
that emit one memory row per hour, drones that only consult memory
at waypoints, wearables that wake every few minutes.

The CLI path opens a fresh SQLite connection per call (see
`CLAUDE.md` §Architecture connection-topology notes), so concurrent
ephemeral invocations are safe as long as the WAL contention stays
modest.

### Recommended polling intervals

| Device class | Mode | GC interval | Checkpoint | Profile |
|---|---|---|---|---|
| Phone (active conversation) | daemon | 30 min | 5 min | semantic |
| Phone (background daemon, idle 95% of the day) | daemon | 4h | 30 min | semantic |
| Pi 4 / Pi 5 (always-on, mains power) | daemon | 30 min | 5 min | semantic |
| Pi Zero 2 W (battery, intermittent) | ephemeral | n/a | n/a | keyword |
| Drone / field sensor (sparse waypoint memory) | ephemeral | n/a | n/a | keyword |
| Wearable (sub-hourly memory emits) | ephemeral | n/a | n/a | keyword |

## 10. Sync patterns — edge device to regional hub

A phone or IoT endpoint typically does **not** want to act as a
peer in the federation mesh — it has intermittent connectivity, it
moves between networks, its IP is unstable, and you don't want
every peer in your fleet trying to push to it.

The deployment pattern that works:

- **Edge device runs `ai-memory serve` as a non-federation node.**
  No peer allowlist, no Ed25519 signing key, no inbound port
  exposed. The substrate runs purely local.
- **Edge device opportunistically pushes to a regional hub** when
  connectivity is available. Use the `/sync/push` HTTP endpoint
  (with HMAC + nonce per `AI_MEMORY_FED_REQUIRE_SIG=1` +
  `AI_MEMORY_FED_REQUIRE_NONCE=1`).
- **Hub is a Tier-2 or Tier-3 node** (single server or rack-scale,
  see [`docs/reference-architectures.md`](reference-architectures.md)).
  The hub holds the durable archive + cross-device memory + the
  source-of-truth FTS5/HNSW for the fleet.
- **Edge device pulls from the hub on demand** when local recall
  misses or returns low-confidence results, via the same
  `/sync/pull` shape.

This is the **mobile-edge tier** documented as topology 9 in
[`docs/reference-architectures.md`](reference-architectures.md#topology-9).

### Mobile-appropriate MCP / HTTP subset

Not every MCP tool / HTTP endpoint is mobile-friendly. The
recommended subset for resource-constrained devices:

| Surface | Mobile-friendly | Notes |
|---|---|---|
| `memory_store` / `POST /memories` | YES | Core write path |
| `memory_recall` / `POST /recall` | YES | Core read path |
| `memory_search` / `GET /memories?q=` | YES | Lightweight FTS5-only path |
| `memory_get` / `GET /memories/{id}` | YES | O(1) by id |
| `memory_link` / `POST /links` | YES | Cheap |
| `memory_capabilities` | YES | Boot-time only |
| `memory_consolidate` | DEFER to hub | LLM-heavy; round-trip to the regional hub instead of running on device |
| `memory_kg_query` | DEFER to hub | Recursive CTE / AGE traversals can blow RAM on a 10k+ corpus |
| `memory_reflect` | DEFER to hub | Triggers LLM chain — too expensive on-device |
| `memory_atomise` | DEFER to hub | Same — LLM curator chain |
| `/sync/push` + `/sync/pull` | YES | The whole point of the edge tier |
| `/metrics` | OPTIONAL | If you're aggregating fleet telemetry; otherwise turn off |

Use `--profile core` or `--profile keyword` on the device to
expose only the mobile-friendly surface; the LLM-heavy tools then
return a `tool not enabled` envelope so the AI client knows to
forward to the hub.

## 11. Examples / use cases

### A. Local AI assistant on a phone, persistent memory

User runs Termux + an Ollama-on-Termux model on a Pixel. ai-memory
sits between them: every Ollama-side conversation persists to
`~/.ai-memory/ai-memory.db`. When the user comes back two days
later and says "remember that thing we talked about?", recall
returns the right memory without an internet round-trip. Battery
hit: negligible (daemon idle ~0.4% / hour).

### B. Field IoT sensor with on-device anomaly memory

A LoRaWAN-connected soil-moisture sensor running OpenWrt on a
Mediatek MT7621 (Cortex-A72-class) embeds an ai-memory CLI in
ephemeral mode. Every hour, the sensor reads its analog inputs,
runs a tiny anomaly detector, and writes the result as a
short-tier memory:

```bash
ai-memory store \
  --title "soil-moisture-anomaly-$(date +%s)" \
  --content "raw=$RAW threshold=$THRESH delta=$DELTA" \
  --tags soil,anomaly --priority 6 \
  --db /data/ai-memory.db
```

Once a day, the sensor pushes its short-tier memories to a
regional hub running on a Pi 5 in the farmhouse. The hub
consolidates patterns across the 200-sensor fleet and lights an
alert in the farmer's dashboard when a cluster pattern emerges.

### C. Drone with episodic recall

A surveying drone runs Linux on a Jetson Orin Nano. On every
waypoint, the drone captures a frame, runs an on-board vision
model, and stores the embedding + waypoint metadata as a
mid-tier memory. On the next survey of the same area, recall
pulls the prior visit's embedding and the drone diffs the
current frame against it — building up an episodic memory of
"this corner of the field looks different than last week"
without needing a cloud round-trip.

The hub on the ground station (a NUC running ai-memory as a
Tier-3 node) accepts the drone's `/sync/push` when it lands and
charges. Cross-flight pattern detection happens on the ground
station, where LLM-heavy consolidation can run without eating
the drone's battery.

### D. Wearable: persistent memory for an on-wrist assistant

A Pebble-class wearable running NuttX or Zephyr is too small for
ai-memory directly. The pattern: a paired phone runs ai-memory in
Termux; the wearable hits the phone over BLE; the phone holds
the persistent memory + bounces queries to a regional hub when
needed. The wearable itself stays a thin client. This is the
canonical "edge of the edge" topology — three tiers (wearable →
phone → regional hub) — described in
[`docs/reference-architectures.md`](reference-architectures.md#topology-9).

### E. Automotive head-unit / infotainment

An automotive head-unit running Android Automotive OS on a
Snapdragon 8295 (Cortex-A78-class) embeds the
`ai-memory-android.tar.gz` artifact. Every driver interaction
that hints at preference ("you like the AC at 68°F", "you prefer
the highway route home from work") gets persisted. On the next
drive, recall personalizes the experience without needing the
cloud. Privacy: the memory stays on the head-unit until the
driver opts into cross-vehicle sync; if opted in, it pushes to
the manufacturer's per-account hub instead of a per-device
cloud account.

---

## Where the artifacts come from

Every `release/v0.7.x` tag publishes (under
[GitHub Releases](https://github.com/alphaonedev/ai-memory-mcp/releases)):

- `ai-memory-{aarch64,x86_64}-{apple-darwin,unknown-linux-gnu}.tar.gz`
  — desktop / server / Pi / Mac binaries
- `ai-memory-x86_64-pc-windows-msvc.zip` — Windows binary
- `ai-memory-ios.xcframework.tar.gz` — iOS xcframework (3 slices)
- `ai-memory-android.tar.gz` — Android `.aar`-shaped archive
  with 4 ABIs under `jniLibs/<abi>/`

The mobile artifacts are produced by `.github/workflows/release.yml`
jobs `mobile-ios` and `mobile-android`. The runtime gate on every
push to `release/**` is the dedicated `.github/workflows/mobile-runtime.yml`.

## Where to file issues

- Build failure on an aarch64-linux board → tag `target:aarch64`
- iOS build / xcframework issue → tag `target:ios`
- Android NDK / cdylib issue → tag `target:android`
- RISC-V build failure → tag `target:riscv` (community-attested, no upstream CI gate yet)
- FFI surface (Swift / JNI binding requests) → tag `area:ffi`,
  reference issue #1068 Layer 2
