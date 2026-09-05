# The wake plane: `ai-memory wake-hub` and the wake sink

> Issues [#3466](https://github.com/alphaonedev/ai-memory-mcp/issues/3466)
> (EPIC), [#3465](https://github.com/alphaonedev/ai-memory-mcp/issues/3465)
> (the bus), [#3467](https://github.com/alphaonedev/ai-memory-mcp/issues/3467)
> (the hub), [#3468](https://github.com/alphaonedev/ai-memory-mcp/issues/3468)
> (identity), [#3469](https://github.com/alphaonedev/ai-memory-mcp/issues/3469)
> (this page: the bus sink).

## What the wake plane is for

Before it existed, `memory_notify` wrote a durable inbox row and dispatched
nothing. A recipient learned it had mail only by polling `memory_inbox`. The
wake plane closes that gap: a committed notify pushes a bounded, content-free
HINT to the recipient in about a millisecond, so the poll becomes a safety net
instead of the delivery mechanism.

Three pieces:

| Piece | Owns |
|---|---|
| `crate::inbox_wake` | the in-process `agent_notified` broadcast bus, one frame per committed notify |
| `crate::wake_sink` | the bridge from that bus to the hub — in-process, or over the hub's socket |
| `crate::wake_hub` | the same-host Unix-domain-socket switch that pushes the hint to connected agents |

## NORMATIVE: keep polling

**A client of the wake plane MUST continue to poll its inbox at least once every
60 seconds** (`wake_sink::BACKSTOP_POLL_MAX`).

This is the rule that makes everything else here safe. The hub holds no durable
truth: the ai-memory inbox row is the record and the wake is only a prompt to go
read it. Every bound in the plane — a full recipient queue, a full hub-wide
egress budget, a full hand-off channel, a lagging bus subscriber, an absent hub
process — may drop a hint. Bounding the backstop poll is what turns each of
those into a bounded LATENCY cost rather than an unbounded correctness one.

Sixty seconds is a CEILING, not a target. A client that observes a
`seq_high_watermark` gap should read immediately rather than wait it out.

## Self-healing after a lost wake

Every wake carries `seq_high_watermark`: the producer's host-wide monotonic wake
counter at the instant the hint was minted. It is deliberately NOT a
per-recipient inbox depth — the bus has no per-recipient counter, and a truthful
one would put a database read on the very latency path this plane exists to
remove.

Read it as *"wakes happened that you did not see"*. The correct response to a
gap is ONE catch-up inbox read. That is fail-safe by construction: a client may
read once more than it strictly had to, and can never conclude that nothing was
missed when something was.

A sink-side per-recipient counter would be strictly worse. When a broadcast
subscriber lags, it never sees the frames that were dropped, so it would hand
clients contiguous numbers across a real gap. Lag is therefore signalled
explicitly, through `InboxWakeSink::on_lagged` and its own metric.

## What a wake carries — and what it cannot

A wake payload is exactly:

```text
{ inbox_row_id, namespace, sender, digest, seq_high_watermark }
```

* `digest` is the SHA-256 of the notification body, so a recipient can
  de-duplicate and verify what it later reads back without the hub ever seeing
  the body.
* There is no body field and no title field, on the bus frame or on the wire.
  The body reaches only the emitter, which digests it.
* The whole encoding is capped. When a long namespace and a long agent id will
  not fit together, fields are shed in a fixed order — `sender`, then
  `namespace`, then `digest` — and `inbox_row_id` and `seq_high_watermark` are
  never shed. A hint that will not fit even then is REFUSED rather than
  truncated: a truncated row id points at the wrong row, and this plane may only
  ever produce fewer results, never wrong ones.

## Who may receive which wake

A substrate wake is addressed DIRECTLY to the recipient agent id and never to a
`#topic`. The hub's route table is keyed by the identity a hello authenticated,
so a wake for `X` can only ever land on a session that authenticated AS `X` —
own-inbox only, which is exactly the scope #3468's delegation verifier grants
until #3505 widens it. A topic-shaped, reserved, empty or over-long recipient is
refused and counted; it is never coerced into something routable.

Wakes are never sourced from the webhook lane. That lane is operator egress,
with a global dispatch semaphore and a subscription-scan ceiling; sourcing an
agent's latency-critical wake from it would make one slow operator webhook the
recipient's wake latency. The `agent_notified` event still fires there for
operator subscribers — the two lanes are fed from the same emitter and are
independent of one another.

## The two deployment shapes

### Co-hosted with the daemon

`wake_sink::in_process::install_in_process(router)` attaches a fire-and-forget
sink to the bus. The encoded frame goes straight to the hub's own
`Router::deliver` — the same injection point a hub connection's own `route_wake`
uses — so a substrate wake and a peer-relayed one are indistinguishable
downstream and obey the same per-recipient queue depth, per-recipient byte cap,
hub-wide egress budget and coalesced offline set. There is one set of bounds to
reason about, not two.

### Hub as a separate process

`wake_sink::uds::install_uds(cfg, credential)` starts a forwarder that is an
ORDINARY hub client over the hub's Unix domain socket: the hub opens with a
challenge, the forwarder answers with a signed hello, and from then on it writes
`wake` frames through the same length-delimited codec and the same frame ceiling
every peer uses. There is no privileged side channel and no second admission
path — the hub applies its peer-credential gate, its identity verifier, its
token buckets and its queue bounds to the daemon exactly as it does to an agent.

## Identity, and why it fails closed

A substrate wake is stamped with the reserved `wake-hub-producer` identity, NOT
with the notifying agent's id. No hub session ever authenticated that agent for
that frame, so putting its id on the frame's `from` would be a claim the hub
never checked. The real sender rides in the wake metadata, where it is plainly
metadata.

`wake-hub-producer` is a reserved agent id, so no wire caller can register it or
claim it through `X-Agent-Id`, an MCP tool argument, or an HTTP body. "May wake
any agent on this host" is therefore an operator grant to one unclaimable name
rather than an authority an agent can talk its way into. The forwarder REFUSES
to start for a credential that authenticates as anything else.

The shipped join credential (`NoJoinCredential`) refuses to sign, so a daemon
with no enrolled producer identity refuses to start a forwarder rather than
opening a socket it could not authenticate on. This mirrors the hub's own
shipped `DenyAllVerifier`. There is deliberately no flag that relaxes either
one: a switch that disables identity verification is a switch that eventually
gets set in production.

## Degrade, never corrupt

The durable inbox row is already committed before a wake fires. A slow, full or
absent hub therefore costs a HINT and a counter — never a committed notify, and
never backpressure applied to the notify path. Concretely:

* Everything on the bus pump is an encode plus a non-blocking enqueue. No
  `.await`, no lock held across one, no I/O.
* The hand-off channel to a separate-process hub is bounded. When it is full
  the new HINT is dropped and counted; the durable write it referred to has
  already committed, so the recipient still finds the row on its next poll.
* Reconnects use jittered exponential backoff capped at the backstop interval,
  so a hub restart cannot produce a synchronised reconnect blast across a fleet.
  The ladder resets only after a connection that actually lasted, so a hub that
  accepts and instantly drops cannot turn the forwarder into a hot loop, and a
  daemon that survived one long outage does not stay stuck at the cap forever.

Every drop cause has its own counter on `wake_sink::SinkMetricsSnapshot` —
unaddressable recipient, unencodable frame, hub queue or egress overflow,
offline-coalesced, offline-unknown, hand-off channel full, hub down, and bus
lag. A hub that silently stopped waking anyone must not look like a quiet fleet.

## Turning it on: the operator ceremony

Nothing pushes wakes until an operator asks for it. The default posture is no
forwarder, no socket and no identity load.

**1. Run the hub.** `ai-memory wake-hub --allowlist <allow.json>` in its own
process (see `docs/CLI_REFERENCE.md`; `--posture` prints the resolved socket,
directory mode and fd budget without binding anything).

**2. Grant the producer name.** The daemon issues its wake sessions under the
reserved principal `wake-hub-producer`, signed by the daemon's OWN enrolled
`daemon` key — the same key it already signs links with. Publish an allowlist
row binding that name to that public key:

```bash
ai-memory identity hub-cache --daemon-producer \
    --include-agent <each agent that may listen> --out <allow.json>
```

`--daemon-producer` is the switch that publishes it. It reads only
`daemon.pub` from this host's owner-only key directory and writes the row with
`bind_authority: "daemon_key_dir"`.

That row is the single, revocable grant that says "this host's daemon may wake
agents on this hub". Drop the switch on the next refresh and the row disappears,
which revokes the daemon's wake authority within a second — the hub revalidates
every established session once per second against the current snapshot. Both the
grant and the revocation are recorded on the `signed_events` audit spine as
`identity.hub_allow` / `identity.hub_revoke`, exactly like an agent's.

There is deliberately no way to publish this row by naming the principal:
`--include-agent wake-hub-producer` is REFUSED, because a reserved principal has no
key history and the store loop would silently omit it, publishing a snapshot
that looked successful and granted nothing.

### What `daemon_key_dir` does and does not attest

It says: the operator of this host, with read access to its 0700 key directory,
asserted that this host's daemon key may wake agents on this hub. It does NOT
claim a possession challenge was answered or that a v97 ledger row backs it —
neither is true, and stamping `possession_proof` would be a lie about the
durable identity root. The hub therefore treats it as delegating authority for
the reserved `wake-hub-producer` name and for NO other principal: that name is
unclaimable on the wire, owns no memories and no namespace, and the only thing
it can do is deliver a content-free wake hint addressed to an agent's own inbox.
A hub build that has never heard of the value maps it to "unrecognised", which
cannot delegate at all — so an older hub reading a newer snapshot fails closed.

**3. Point the daemon at the hub.** In `config.toml`:

```toml
[wake_hub]
sink_socket = "/run/user/1000/ai-memory/wake-hub.sock"
```

Restart `serve`. The startup log names the enrolled public key it will issue
under, so you can check it against the row you published.

If the sink is configured but the daemon has no enrolled key — or a
public-only one — it REFUSES to start the forwarder, logs the exact
remediation at ERROR, and keeps serving. It does not open a socket it could not
authenticate on, and it does not take the durable substrate down over a hint it
cannot push.

### Why the daemon's own key, and not a key of its own

`wake-hub-producer` is a reserved agent id: no wire caller can register or
claim it. It deliberately has NO enrolled root of its own. Minting one would
mean a second private key on the host, with its own enrolment ceremony, its own
rotation and its own revocation story — a second identity root, which is
exactly what "one identity root" forbids. Instead the daemon's already-enrolled,
already-proven root is the sole authority, `wake-hub-producer` is a scoped NAME
that root may speak under on the wake plane, and the allowlist row is the
operator's explicit, revocable grant that says so. The per-connection session
key is generated in memory and never written anywhere, so there is no
credential file to steal and nothing to rotate.

### The co-hosted shape

`wake_sink::in_process::install_in_process(router)` is available as a library
call and is exercised by the test suite, but nothing in `serve` hosts a hub in
this build — `ai-memory wake-hub` runs the hub as its own process. When a
`serve`-hosted hub lands, wiring it is one line at the same boot site.

## Operating the hub

> Issue [#3471](https://github.com/alphaonedev/ai-memory-mcp/issues/3471) — the
> ops surface: metrics, the health probe, the SIGTERM drain, the supervisor
> units, and the `doctor` posture check.

`ai-memory wake-hub --posture` resolves and prints the socket, directory mode,
fd budget, drain deadline and identity verifier **without binding anything**,
so it is safe to run against a host already serving a hub. `--allowlist` names
the derived public snapshot of enrolled agent keys the delegation verifier
reads; the hub itself never opens the store. Full flag reference:
`docs/CLI_REFERENCE.md`.

### Is it up? — `wake-hub --health`

```bash
ai-memory wake-hub --health          # human report; exit 0 reachable, 2 not
ai-memory wake-hub --health --json   # machine-readable, same exit codes
```

The probe is an **ordinary hub client**. It connects to the configured socket,
waits for the hub's opening challenge frame, and closes. That is the whole
probe, and the three things it deliberately is NOT are what make it safe:

* **Not a privileged side channel.** There is no admin socket and no status
  endpoint. A health surface that bypassed the hub's own admission path would
  be an unauthenticated way to learn its state — and, worse, would stop
  testing the path that actually matters.
* **Not a bypass of the peer-credential gate.** The probe is subject to
  `SO_PEERCRED` / `getpeereid` like any peer. Run as the wrong user it is
  denied and reports `unreachable`, which is the correct answer: from that
  user, the hub *is* unreachable.
* **Not an authenticated session.** It presents no `hello`, holds no key
  material, and is refused everything past the challenge — so it cannot
  enumerate agents, join topics or inject a wake, and it needs no credential,
  which is what makes it runnable from a supervisor where no agent identity
  exists.

Cost to the hub is one short-lived connection bounded by a 2 s budget, against
a pre-auth budget of 4 frames/s that the probe never spends (it sends zero
frames). Every outcome that is not "a well-formed challenge arrived" is
`unreachable` with a named cause and remedy — `socket_missing`,
`not_a_socket`, `connection_refused` (a stale socket with no listener),
`permission_denied`, `timeout`, `unexpected_frame` — because a supervisor that
reads "healthy" from an inconclusive probe is worse than no probe.

### What it reports — the metrics

The hub's counters, gauges and histograms are read through one stable JSON
shape (`wake_hub::metrics::MetricsSnapshot::to_json`), published at rest by
`wake-hub --posture --json` under `metrics_schema` so an exporter can be
written against a documented contract:

| Family | Answers |
|---|---|
| `connections_current`, `recipients_current` | how many agents are attached, and how many hold a route |
| `queue.queued_bytes_current` / `queued_frames_current` | how much is waiting, under BOTH per-recipient bounds — bytes and frames are different faults with different remedies |
| `queue.slow_consumers_current` / `slow_consumer_events_total` | who is falling behind, counted BEFORE anything is dropped |
| `drops.*` | WHY a delivery was refused: `recipient_queue_full` (one slow reader), `global_egress_full` (the hub is saturated), `channel_full` (a burst deeper than the queue), `write_failed` (accepted then unwritable), `offline_unknown` |
| `denied.*` | peer credential, connection ceiling, hello, malformed, forged `from`, rate limit |
| `fanout_latency_us`, `wake_latency_us` | `count` / `mean` / `max` / `p50` / `p99` — fan-out is the hub-internal hand-off span, wake latency is mint-to-delivery |

Two properties are load-bearing. The histograms are **fixed-bucket and
allocation-free** — an observability surface the hub can be made to allocate
would be a denial-of-service surface, not observability — so a bucketed
quantile is reported as the containing bucket's UPPER bound, a conservative
over-estimate that can make the hub look slower than it is and never faster.
And a quantile with no observations behind it is `null`, never `0`: "no
traffic yet" and "instantaneous" are different facts and an alert rule must be
able to tell them apart. Mint-to-delivery crosses a wall-clock boundary, so it
is advisory: a wake with no stamp records nothing, and a peer whose clock runs
ahead records `0` rather than an underflowed enormous value.

### Shutting it down — the bounded drain

On `SIGTERM` or `SIGINT`, in this order and no other:

1. **Stop accepting.** The listener closes first, so a peer arriving
   mid-shutdown is refused by the kernel rather than accepted into a hub that
   is about to stop reading it.
2. **Ask every session to go.** Each reader is woken and each writer gets its
   close sentinel. **Nothing content-bearing is emitted** — no goodbye frame,
   no last wake. The hub holds no durable truth, so there is nothing it could
   owe a peer at shutdown; the committed inbox row and the `<=60 s` backstop
   poll are the guarantee, exactly as at every other moment.
3. **Wait, bounded.** At most 5 s (`wake_hub::limits::DRAIN_DEADLINE_MS`) for
   the connection gauge to reach zero, then exit anyway with a WARN naming the
   residual. An unbounded drain is a hung `systemctl stop` that ends in
   `SIGKILL` — strictly worse, because the socket then survives the process.
4. **Unlink our own socket, and only ours.** The path must still be a socket
   AND carry the `(device, inode)` this process created. Without the inode
   check, a hub slow to drain while its replacement had already bound a fresh
   socket at the same path would delete the REPLACEMENT's socket, and every
   agent on the host would be talking to a live process through a path that no
   longer exists. When ownership cannot be established the file is left for
   the next start-up probe, which connects to it before unlinking anything.

The process exits `0` after a completed drain, so `systemctl stop` and
`launchctl bootout` do not record a failure for the thing they asked for.

### Supervisor units

| Platform | Template |
|---|---|
| systemd | `packaging/systemd/ai-memory-wake-hub.service` |
| launchd | `scripts/templates/dev.alphaone.ai-memory.wake-hub.plist` |

Both pin the file-descriptor budget to `wake_hub::limits::DESIRED_NOFILE`
(4096) — `LimitNOFILE=` on systemd, `SoftResourceLimits`/`HardResourceLimits`
`NumberOfFiles` on launchd. **This is the point of the templates:** macOS
ships a default soft `RLIMIT_NOFILE` of 256, which lands `EMFILE` at exactly
the 256-agent scale the hub is designed for. At start-up the hub raises its own
soft limit toward that value where the hard limit allows, sizes its connection
ceiling from what it actually got (WARNing when that is below the target), and
REFUSES to bind at all when the budget cannot cover `MIN_CONNECTION_CEILING`
connections plus `FD_HEADROOM` descriptors — a smaller hub is honest, a hub
that lies about its capacity is not. The systemd unit additionally restricts
the address family to `AF_UNIX`: the wake plane is same-host by construction,
so the kernel enforces that as well as the code. Its `ExecStartPost` runs
`--health`, so a unit that reports "started" has actually been reached — a
claim that holds **only because that probe retries**. `Type=simple` lets
systemd run `ExecStartPost` as soon as it has forked the main process, before
the hub has bound, and the hub sends no `sd_notify`; the unit therefore retries
the probe for about five seconds across the bind race and fails the unit only
if the hub is still unreachable after that. A single-shot probe would fail
every start and, with `Restart=on-failure`, convert a healthy host into a
restart loop. The unit also sets `RuntimeDirectoryPreserve=yes`, so the
allowlist snapshot it tells you to publish at `/run/ai-memory/hub-allow.json`
survives a stop or restart instead of being deleted with the runtime directory
— which would leave the restarted hub admitting nobody. `/run` is a tmpfs, so
that path still does not survive a **reboot**; republish it after boot.

### `ai-memory doctor`

`doctor` carries a **Wake hub (#3471)** section — filesystem and `getrlimit`
only, no bind, no connect, no database. A live socket whose mode or ownership
is wrong is **Critical** (that is an exposure on this host right now); a
file-descriptor budget below the desired value on a host that runs a hub is a
**Warning**, escalating to Critical only below the floor at which the hub would
refuse to start; an installed supervisor unit is **informational** and its
absence is never a finding, because running the hub in the foreground or under
another supervisor is a legitimate deployment. On a host with no `[wake_hub]`
configuration and no socket on disk the section reports `configured = no` and
nothing else.
