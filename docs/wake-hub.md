# The wake plane: `ai-memory wake-hub` and the wake sink

> Issues [#3466](https://github.com/alphaonedev/ai-memory-mcp/issues/3466)
> (EPIC), [#3465](https://github.com/alphaonedev/ai-memory-mcp/issues/3465)
> (the bus), [#3467](https://github.com/alphaonedev/ai-memory-mcp/issues/3467)
> (the hub), [#3468](https://github.com/alphaonedev/ai-memory-mcp/issues/3468)
> (identity), [#3469](https://github.com/alphaonedev/ai-memory-mcp/issues/3469)
> (the bus sink), [#3470](https://github.com/alphaonedev/ai-memory-mcp/issues/3470)
> (this page: the client).

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
| `crate::wake_client` | the CLIENT: one long-lived session, one catch-up inbox read per hint, and the bounded poll that makes losing the hub cost latency only |

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

## The client: `ai-memory wake-listen`

The plane is only useful if something listens on it. `ai-memory wake-listen`
(#3470) is that something, and it is what replaces the fleet's three-minute
`ai-memory inbox` cron: one process, one session, one inbox read per event
instead of one process boot per poll.

```bash
# once, per agent, on the host that will listen
ai-memory identity delegate --scope a2a-hub --agent-id ai:alice --hub-id ai-memory-wake-hub

# then, long-lived
ai-memory wake-listen --agent-id ai:alice --json
ai-memory wake-listen --agent-id ai:alice --exec 'my-notifier'

# or, for a one-shot "block until there is mail, then print it"
ai-memory inbox --wait --timeout 300 --agent-id ai:alice
```

### What it reads, and how often

Exactly ONE catch-up inbox read per event, through the same `memory_inbox`
funnel every other surface uses — never a read per queued hint:

| Event | Why it reads |
|---|---|
| welcome | mail may have arrived while this agent was offline |
| welcome with `lagged` | the hub's offline id set overflowed, so its id list cannot be trusted |
| `wake` | a hint arrived naming a row |
| `wake` with a `seq_high_watermark` gap | wakes happened that this listener did not see |
| backstop tick | the bounded poll, always armed |

The backstop's clock is reset by every catch-up read, hub-driven or not, so the
guarantee is "at most `BACKSTOP_POLL_MAX` since the LAST read" rather than a
fixed schedule that fires right after a wake. A healthy hub therefore costs at
most one idle read per minute per agent, not one per wake plus one per minute.

`--poll-secs` is REFUSED above 60 rather than clamped: a listener that silently
polled less often than the plane's own contract would be reporting a guarantee
it does not provide.

### One identity root, and every check fails closed

The listener loads the bundle `ai-memory identity delegate --scope a2a-hub`
wrote — `<key-dir>/<agent-id>.a2a-hub.json`, mode 0600 — which holds a
DELEGATED private key and never the enrolled one. There is no second identity
root and no second enrolment ceremony; the agent's enrolled key is still the
sole authority, and the delegation is a short-lived certificate it minted.

Before a byte reaches the wire the listener refuses a bundle that is:

* not mode 0600, not owned by the caller, or reached through a symlink;
* a version this build does not understand;
* minted for a different hub, or for a different agent than the one being
  watched;
* holding a private key that is not the one its certificate authorises;
* carrying a certificate that does not verify under the agent's ENROLLED public
  key in the same key directory;
* outside its validity window (refused locally, with the re-mint command in the
  message, rather than as an opaque `401` after a reconnect ladder).

It also checks the socket the way the hub hardened it: an owner-only (`0700`)
directory holding an owner-only (`0600`) socket, both owned by the caller.
Dialling a socket another local user could have created would be handing the
handshake to whoever won that race.

There is deliberately no flag that skips any of this — the same reasoning that
keeps `--insecure` off `ai-memory wake-hub`.

### Degrade, never corrupt

Every failure mode here costs LATENCY:

* **No hub configured, hub down, hub refusing.** The bounded poll IS the
  delivery mechanism. That is the documented degraded mode, not an error.
* **Reconnects.** Jittered exponential backoff capped at the backstop, with the
  ladder resetting only after a session that actually lasted — so a hub that
  accepts and instantly drops cannot become a hot loop, and a fleet restart
  cannot produce a synchronised reconnect blast.
* **A slow consumer.** Signals cross to the consumer through a bounded channel
  using `try_send`. A full channel means a catch-up read is already queued and
  will see every row a dropped signal referred to, so the drop coalesces reads
  rather than losing them — and it is counted, because a listener that silently
  stopped reading must not look like a quiet inbox.
* **A failed catch-up read.** Logged; the row is already committed and the next
  signal — at worst the backstop — reads it again.
* **A hung `--exec` hook.** Bounded at 30 s and killed, so one slow notifier
  cannot become a listener that stops reading.

### The exec hook carries metadata, never a body

`--exec` runs `sh -c <cmd>` with the wake hint in the ENVIRONMENT (never on the
command line, so wire-sourced values reach neither `ps` output nor shell
word-splitting):

`AI_MEMORY_WAKE_REASON`, `_AGENT_ID`, `_HUB_ID`, `_INBOX_ROW_ID`, `_NAMESPACE`,
`_SENDER`, `_DIGEST` (lowercase hex SHA-256 **of the body**), `_SEQ`,
`_MISSED`, `_PENDING`, `_INBOX_COUNT`.

`_DIGEST` is what lets a hook verify what it later reads without the hub ever
having seen it. There is no body variable because there is no body on the wire.
These variables are EMITTED by the listener, not read by the substrate, so they
carry no precedence ladder and appear in no `AI_MEMORY_*` resolution table.

### Replacing a polling fleet

A fleet that coordinates through `memory_notify` + `ai-memory inbox` on a timer
converts to the wake plane one agent at a time, and never all at once:

```bash
# 1. once per agent, on the host that will listen
ai-memory identity delegate --scope a2a-hub --agent-id <agent> --hub-id ai-memory-wake-hub

# 2. replace `sleep 180; ai-memory inbox --agent-id <agent> --json`
ai-memory inbox --wait --timeout 180 --agent-id <agent> --json

# 3. or, for a long-lived worker, replace the loop entirely
ai-memory wake-listen --agent-id <agent> --exec 'my-handler'
```

Nothing about the durable side changes: the same rows, the same read, the same
output. What changes is that the read happens when there is mail rather than
every three minutes — and, because the `<=60 s` backstop is always armed, an
agent whose hub is unreachable is strictly no worse off than the poller it
replaced.

The `sdk/python/swarm` acceptance harness converts the same way: set
`SWARM_WAKE_HUB_SOCKET` + `SWARM_WAKE_HUB_BUNDLE_DIR` and its consumer lanes
wait for the wake instead of racing the write. Leaving them unset keeps the
harness byte-identical to its pre-#3470 behaviour, which is what makes the
switch safe to roll out per fleet rather than per release.

### `ai-memory inbox --wait`

The one-shot form: block on the wake plane, then perform and print the read
exactly as `ai-memory inbox` does. `--timeout` bounds the wait, and on expiry
the read STILL happens — a timeout means "nothing arrived in that window",
never "skip the durable truth". **Omitting `--timeout` does not mean waiting
forever:** the backstop tick is itself a return, so a wait without it lasts at
most one poll interval (`<= 60 s`, `wake_sink::BACKSTOP_POLL_MAX`).

A hub that is merely DOWN is already covered by the always-armed backstop: the
credential loads, the session loop backs off, and the poll returns on schedule.
When the CREDENTIAL itself will not load — no `ai-memory identity delegate` was
ever run on this host, the bundle expired, or it was minted for another hub —
`--wait` logs that refusal once at `WARN` with its cause chain and then waits
on the bounded poll anyway. That is deliberate: `--wait` is the drop-in for
`sleep 180; ai-memory inbox`, and a version that returned immediately on a
credential error would replace a paced poll with a hot loop. `ai-memory
wake-listen` keeps the hard refusal, because an operator who started the
listener explicitly asked for a hub session and needs to see why it will not
open.

## Operating the hub

See `docs/CLI_REFERENCE.md` for `ai-memory wake-hub`, including `--posture`
(resolve and print the socket, directory mode and fd budget without binding
anything) and `--allowlist` (the derived public snapshot of enrolled agent keys
that the delegation verifier reads; the hub itself never opens the store).
