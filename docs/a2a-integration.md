# Integrate any agent with the A2A wake plane

The wake plane shipped in ai-memory v1.0.0. This path takes a shell-driven
Claude Code, Codex or Grok agent, a daemon, an SDK program, or a one-shot script
from enrolment to receiving hints and exchanging durable messages. You do not
need to implement the wire protocol. Use the CLI or SDK client on the same host
as the hub, with access to the intended ai-memory store.

## 1. The model in one page

`memory_notify` writes a durable inbox row. The daemon's wake sink forwards a
content-free hint to the local wake-hub. The recipient reads `memory_inbox` to
obtain the message. **The hint is advisory, the row is the record, the bounded
poll is the guarantee.** Every receiver must read at least once every 60 seconds
while running, even if the hub is unavailable. A gap or lag signal means one
catch-up read, not one read for every missing hint.

```text
sender -> notify -> durable inbox row
                       |
                 local wake sink -> local hub -> recipient
                       ^                         |
                       +------ inbox read -------+
```

The plane carries no message bodies or titles, has no cross-host hop of its
own, and introduces no second identity root. The hub has no database access.
A hint identifies a row and normally includes its body digest; read the row
through the normal authorization boundary before acting. Never execute text
from a hint or treat a notification as authorization for privileged work.

Millisecond wakes, including a sub-millisecond hub hop, are **design targets**,
not published measurements. Acceptance-latency measurement
[#3473](https://github.com/alphaonedev/ai-memory-mcp/issues/3473) remains open.
The implementation and certification stance have shipped; measurement has not.

## 2. Choose your receive pattern

Complete section 3 before running the hub-backed examples.

| Your agent | Receive pattern | Cost and responsibility |
|---|---|---|
| Long-lived daemon or loop-driven agent | `ai-memory wake-listen --json` or `--exec` | One session; one catch-up inbox read per event, plus bounded backstop reads. The JSON lines and hook environment contain metadata, not bodies. |
| Shell loop or one-shot script | `ai-memory inbox --wait --timeout N` | One process spawn and session attempt per wait/read. Drop-in replacement for `sleep N; ai-memory inbox`; may return early on a wake. |
| Agent cannot hold a session | Plain `memory_inbox` polling | One read per interval, with no wake latency benefit; one process spawn per poll if using the CLI. Keep the interval at most 60 seconds. |
| Python or TypeScript service | SDK `WakeListener` | One session; your callback performs the catch-up read. Keep model work outside the callback. |

A daemon can consume one JSON line per event:

```bash
ai-memory --agent-id "$AGENT" wake-listen --json --poll-secs 30
```

For a small notification hook, this complete example records metadata for a
separate worker. Provision `WAKE_EVENTS` as an owner-only file first. It does
not run a model once per hint:

```bash
export WAKE_EVENTS="$PWD/a2a-demo/wake-events.log"
(umask 077; touch "$WAKE_EVENTS")
ai-memory --agent-id "$AGENT" wake-listen --poll-secs 30 \
  --exec 'printf "%s\n" "$AI_MEMORY_WAKE_REASON" >> "$WAKE_EVENTS"'
```

This hook writes reason lines; use `--json` redirected to a separate file if
you want full JSON metadata. The hook is bounded at 30 seconds;
use it to signal a worker, not to run a potentially long model pass. The CLI
already reads the inbox before emitting; your worker still needs to read the
bodies. Welcome, gap, lagged and backstop events can have no row ID.

For a one-shot shell read:

```bash
ai-memory --agent-id "$AGENT" inbox --wait --timeout 30 --json
```

Timeout is not an error: it still reads and prints the inbox, possibly empty.
An empty welcome does not end the wait. Even with no explicit timeout, the
bounded backstop returns within its interval. Missing or expired credentials
cause this command to warn and wait on the fallback; `wake-listen` instead
refuses startup so you can repair its bundle.

For an MCP agent without a session, call `memory_inbox` with these arguments
on a scheduler that runs at most 30 seconds apart; `agent_id` must match the
MCP caller identity:

```json
{"agent_id":"ai:worker","unread_only":true,"limit":500}
```

Process the returned `messages`, deduplicate their `id` values, and retain an
application checkpoint. An inbox listing does not acknowledge successful work.
A shell equivalent is `ai-memory --agent-id "$AGENT" inbox --json` on that
scheduler. Do not sleep only when the previous read was empty.

Python can use the shipped SDK and its existing HTTP authentication settings:

```python
import os
from ai_memory import AiMemoryClient
from ai_memory.wake import DelegationBundle, WakeListener

agent = os.environ["AGENT"]
bundle = DelegationBundle.load(
    os.environ["BUNDLE"], hub_id=os.environ["HUB"]
)
client = AiMemoryClient(
    base_url=os.environ["API_BASE"],
    api_key=os.environ["API_KEY"], agent_id=agent,
)
def catch_up(signal):
    if signal.reason == "subscribed":
        return
    # Replace printing with a durable local queue; model work runs separately.
    print(client.inbox(agent_id=agent, limit=500), flush=True)

WakeListener(os.environ["SOCKET"], bundle, catch_up).run()
```

For a Node.js TypeScript service using the shipped package:

```typescript
import { AiMemoryClient } from "@alphaone/ai-memory";
import { DelegationBundle, WakeListener } from "@alphaone/ai-memory/wake";

function setting(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Set ${name}`);
  return value;
}
const bundle = DelegationBundle.load(setting("BUNDLE"), { hubId: setting("HUB") });
const client = new AiMemoryClient({
  baseUrl: setting("API_BASE"), apiKey: setting("API_KEY"), agentId: setting("AGENT"),
});
let reading = false;
let pending = false;
async function catchUp(): Promise<void> {
  pending = true;
  if (reading) return;
  reading = true;
  try {
    do {
      pending = false;
      const { messages } = await client.inbox({ limit: 500 });
      // Replace printing with a durable local queue; run the model separately.
      console.log(messages);
    } while (pending);
  } finally {
    reading = false;
  }
}
await new WakeListener(setting("SOCKET"), bundle, (signal) => {
  if (signal.reason !== "subscribed") {
    void catchUp().catch((error: unknown) => console.error("Inbox read failed", error));
  }
}).run();
```

These callbacks demonstrate reception; use the journal and idempotency rules
in section 5 before attaching business side effects. Keep HTTP requests bounded
so a stalled read does not defeat the fallback. The Python and TypeScript SDKs do not read the inbox for you. Both retain the
bounded fallback and reconnect with backoff. Configure client TLS credentials
as described in the [Python SDK guide](../sdk/python/README.md) and
[TypeScript SDK guide](../sdk/typescript/README.md) when mTLS is enabled.

## 3. Enrolment, end to end

Use an installed v1.0.0 binary. Choose one stable agent ID per participant and
one stable hub ID per host. The following is a **fresh local SQLite example**,
run from the same directory in each terminal under the same OS user. Replace
the example agent/type identifiers with your choices. For an existing service,
use its actual store and key directory; do not generate replacement daemon keys.
For PostgreSQL, provision registration and proof-of-possession binding through
the daemon's admin HTTP/SDK surfaces (see the [API reference](API_REFERENCE.md)).
The local `agents register` and `agents bind-key` commands below operate on
SQLite. `identity hub-cache` and `identity delegate` support the configured
PostgreSQL store URL channels in a `sal-postgres` build; never enrol in a
substitute SQLite database.

```bash
umask 077
mkdir -p a2a-demo/store a2a-demo/keys a2a-demo/run a2a-demo/config/ai-memory
chmod 700 a2a-demo a2a-demo/store a2a-demo/keys a2a-demo/run
export AI_MEMORY_DB="$PWD/a2a-demo/store/memory.db"
export AI_MEMORY_KEY_DIR="$PWD/a2a-demo/keys"
export XDG_CONFIG_HOME="$PWD/a2a-demo/config"
export AGENT='ai:worker'
export COORDINATOR='ai:coordinator'
export HUB='example-hub'
export SOCKET="$PWD/a2a-demo/run/wake.sock"
export ALLOWLIST="$PWD/a2a-demo/run/allow.json"
export BUNDLE="$AI_MEMORY_KEY_DIR/$AGENT.a2a-hub.json"

# Fresh installation only: producer uses this host's daemon key.
ai-memory identity generate --agent-id daemon
for participant in "$AGENT" "$COORDINATOR"; do
  ai-memory identity generate --agent-id "$participant"
  ai-memory agents register --agent-id "$participant" --agent-type ai:custom
  public_key=$(ai-memory identity export-pub --agent-id "$participant")
  ai-memory agents bind-key --agent-id "$participant" --pubkey="$public_key"
done

ai-memory identity hub-cache --daemon-producer \
  --include-agent "$AGENT" --include-agent "$COORDINATOR" --out "$ALLOWLIST"

cat > "$XDG_CONFIG_HOME/ai-memory/config.toml" <<CONFIG
[wake_hub]
socket = "$SOCKET"
sink_socket = "$SOCKET"
hub_id = "$HUB"
allowlist = "$ALLOWLIST"
CONFIG

# Separate terminal/supervisor, with the same environment; stays running.
ai-memory wake-hub --socket "$SOCKET" --hub-id "$HUB" --allowlist "$ALLOWLIST"
```

Before the snapshot becomes 60 seconds old, start its refresher in another
terminal or supervisor. Each export is the **complete** retained set. Repeat
`--include-agent` for every participant, not just the newest one:

```bash
while true; do
  ai-memory identity hub-cache --daemon-producer \
    --include-agent "$AGENT" --include-agent "$COORDINATOR" --out "$ALLOWLIST" || exit 1
  sleep 30
done
```

Now mint the listener bundle, then run the daemon with this configuration in
its own terminal. A production deployment uses the existing service supervisor
and its configured bind/TLS settings; the fresh example uses `serve` defaults.

```bash
ai-memory identity delegate --scope a2a-hub --agent-id "$AGENT" --hub-id "$HUB"
ai-memory identity delegate --scope a2a-hub --agent-id "$COORDINATOR" --hub-id "$HUB"
ai-memory serve
```

`generate` creates local key material only. `register --agent-type <type>`
creates the durable agent record; `ai:<name>` accepts arbitrary agent types.
`bind-key` proves possession and anchors its public key in the identity ledger.
`hub-cache` derives public admission authority from that ledger. The
`--daemon-producer` entry lets this daemon forward hints; it is not a new root.
`socket` configures receivers and the hub, while `sink_socket` enables the
**daemon's** forwarder. Setting only `socket` does not enable sending wakes.
`delegate` grants a time-bounded join for this agent and this hub.

The bundle carries a **DELEGATED** private key, never the enrolled one. Protect
it as mode 0600 in an owner-only directory. Rust listeners also need the
matching enrolled public material in their key directory, not its private half.
Bundles expire (default TTL is one hour). Re-mint before expiry using a fresh
path and restart the listener with that path:

```bash
ai-memory identity delegate --scope a2a-hub --agent-id "$AGENT" \
  --hub-id "$HUB" --out "$AI_MEMORY_KEY_DIR/$AGENT.renewed.a2a-hub.json"
ai-memory --agent-id "$AGENT" wake-listen \
  --bundle "$AI_MEMORY_KEY_DIR/$AGENT.renewed.a2a-hub.json" --json
```

Use another new path on the next renewal. `inbox --wait` uses the default
bundle path: stop that receiver, move its old bundle aside, mint to the now-free
default path, then restart. Existing paths and symlinks are refused; overwriting
a bundle is not renewal. A running listener does not automatically adopt a
newly minted file.

To revoke hub participation, omit the agent from the next complete cache
export. Omit `--daemon-producer` to revoke forwarding. Sessions revalidate
against the current snapshot once per second. Revoking an enrolled key with
`agents revoke-key` also removes its eligibility on refresh; use
`identity succeed` for key succession, not forced generation. Expiry alone
ends a delegation without revoking the enrolled identity or its history.

## 4. Sending

An agent-to-agent message addresses the peer; an agent-to-coordinator message
addresses the coordinator's enrolled ID. The coordinator is an ordinary inbox
participant, not a privileged route. To reply, target the sender from the
**durable row**. Always set the sender explicitly.

```bash
ai-memory --agent-id "$AGENT" notify --target-agent-id "$COORDINATOR" \
  --title 'Pass complete' --payload 'Review is ready.' --json
```

The CLI example and shell gate use SQLite. PostgreSQL receivers should use
the HTTP SDK inbox against their configured daemon; do not point these local
CLI commands at a substitute SQLite store. The CLI writes to its selected local store. Its process-local event bus is not
the running daemon's bus: use the daemon HTTP or MCP surface when you want its
configured wake sink and federation fanout. The same durable row remains
readable when a local CLI write is discovered by the timed fallback.

For immediate daemon-driven hints, set `API_BASE` to your daemon's HTTPS base
URL and supply your approved API key and TLS files through these placeholders:

```bash
curl --fail-with-body --silent --show-error \
  --cacert "$CA_CERT" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" \
  -H "X-API-Key: $API_KEY" -H "X-Agent-Id: $COORDINATOR" \
  -H 'Content-Type: application/json' \
  "$API_BASE/api/v1/notify" \
  --data '{"target_agent_id":"ai:worker","title":"Next batch","content":"Please process the queued work."}'
```

For the fresh loopback-only demo, set `API_BASE` to the HTTP address reported
by `serve` and omit the TLS options and X-API-Key header when no API key
is configured. The HTTPS example is for a provisioned service.

`POST /api/v1/notify` requires `target_agent_id`, `title`, and a string body
(`content` or `payload`; send exactly one). `X-Agent-Id` determines the sender.
An optional body `agent_id` must match that header or the request is refused;
it cannot impersonate a different sender. API authentication and mTLS still
apply. The receipt's row ID confirms storage, not that an agent has processed
it. Read with `GET /api/v1/inbox` using the recipient's `X-Agent-Id`, or use
`memory_inbox` through that recipient's MCP session.

## 5. Drive an agent loop from wakes

Run one pass per **batch**, not per wake: one pass per hint will thrash under a
burst. Also, an agent with **no timed fallback** runs only when someone wakes
it; if its coordinator goes quiet it stops. Keep timed inbox reads even when
idle. To continue unfinished work without external input, use
**self-continuation**: after a successful pass, send a notify to your own ID
while work remains. When finished or blocked, stay silent. Prefer the HTTP
shape above for a prompt self-wake; a local CLI self-notify is found by the
fallback. Do not self-notify merely because the inbox was empty.

Save the following as `wake-gate.sh`. It requires Bash, jq and the enrolled
CLI environment from section 3. Supply an executable adapter as `AGENT_PASS`;
its sole argument is a JSON array of rows, and exit zero means the whole batch
has been durably handled. The adapter may launch any CLI agent. It must treat
row IDs as idempotency keys because a crash after a side effect but before the
checkpoint can replay that batch. `GATE_STATE` is a private directory used by
exactly one gate instance. Never delete it just to clear a retry.

```bash
#!/usr/bin/env bash
set -euo pipefail
: "${AGENT:?set AGENT}" "${AGENT_PASS:?set an executable adapter}"
: "${GATE_STATE:?set a private state directory}"
umask 077
mkdir -p "$GATE_STATE"
chmod 700 "$GATE_STATE"
state="$GATE_STATE/state.json"
batch="$GATE_STATE/batch.json"
if [[ ! -f "$state" ]]; then
  printf '%s\n' '{"done":[],"pending":[]}' > "$state"
fi
worker=''
cleanup() {
  if [[ -n "$worker" ]]; then
    kill "$worker" 2>/dev/null || true
    wait "$worker" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

collect() {
  ai-memory --agent-id "$AGENT" inbox "$@" --limit 500 --json > "$GATE_STATE/inbox.json"
  jq -e '.messages | type == "array"' "$GATE_STATE/inbox.json" > /dev/null
  # This API has no inbox cursor. A full page cannot prove complete coverage.
  if [[ $(jq '.messages | length' "$GATE_STATE/inbox.json") -ge 500 ]]; then
    printf '%s\n' 'Inbox page full: reconcile older rows before resuming.' >&2
    exit 1
  fi
  jq --slurpfile incoming "$GATE_STATE/inbox.json" '
    .done as $done |
    .pending = ([.pending[], $incoming[0].messages[]] | unique_by(.id) |
      map(select(.id as $id | $done | index($id) | not)))
  ' "$state" > "$state.next"
  mv "$state.next" "$state"
}

collect  # startup reconciliation, including a batch interrupted by a crash
while true; do
  if [[ -n "$worker" ]] && ! kill -0 "$worker" 2>/dev/null; then
    if wait "$worker"; then
      jq --slurpfile batch "$batch" '
        .done = ((.done + ($batch[0] | map(.id))) | unique) |
        .done as $done |
        .pending |= map(select(.id as $id | $done | index($id) | not))
      ' "$state" > "$state.next"
      mv "$state.next" "$state"
    else
      printf '%s\n' 'Agent pass failed; pending batch retained for retry.' >&2
    fi
    worker=''
  fi
  if [[ -z "$worker" ]] && jq -e '.pending | length > 0' "$state" > /dev/null; then
    sleep 1  # debounce: coalesce the burst before launching a pass
    collect
    jq '.pending' "$state" > "$batch"
    "$AGENT_PASS" "$batch" &
    worker=$!
  fi
  # Reads continue while the model works; empty timeouts do not launch a pass.
  collect --wait --timeout 30
done
```

The first read reconciles startup state. Later reads block on wakes with a
bounded timeout; a debounce read gathers the rest of a burst. New rows received
while a pass runs stay pending for the next batch. Failed passes retain pending
rows and retry after the next bounded wait. Launch with:

```bash
export GATE_STATE="$PWD/a2a-demo/gate"
export AGENT_PASS='./your-agent-pass'
bash wake-gate.sh
```

`your-agent-pass` is your adapter, not an ai-memory command. Keep its processing
bounded and supervise it: a hung adapter does not stop this gate's inbox reads,
but it prevents the next pass. A worker with child processes must propagate
termination to them. The journal grows with handled IDs; archive it only after
reconciling inbox retention and replay requirements. The 500-row guard is
intentional: the inbox API has no cursor and a full newest-page result cannot
prove there are no older rows. Reconcile with the store's authorized listing
and retention workflow before restarting; never silently discard that backlog.

## 6. Multi-host

Run one hub per host. Rows cross hosts through ai-memory federation, with
mutual TLS, signed pushes, peer signing-key enrolment and namespace-scoped
attestation. The receiving host's local plane completes the intended hop.
The hub itself cannot bridge hosts; mounting a socket remotely does not create
a supported cross-host transport.

**Current limitation:** federation receive/apply does not currently publish a
receiving-host inbox wake. The remaining federation-to-local-wake integration is
tracked in [#3631](https://github.com/alphaonedev/ai-memory-mcp/issues/3631).
Until that path is complete, the receiving agent's bounded inbox poll discovers
the replicated row. Cross-host delivery is not a measured millisecond promise.
See the [federation guide](federation.md) for peer configuration.

Enrol both the transport certificate pin and the peer's Ed25519 signing key.
A public-only import uses the peer ID configured by the receiving daemon:

```bash
ai-memory identity import --agent-id "$PEER_ID" --pub "$PEER_PUBLIC_KEY_FILE"
```

Permit the intended original senders in the receiving peer's
`allowed_sender_agent_ids`. Without that rule their sender identities do not
survive the hop. Namespace attestation policy still applies independently of
transport authentication and sender preservation.

## 7. Security model

There are two admission gates. First, kernel peer credentials bind a local
socket client to an OS user; Linux uses `SO_PEERCRED`, macOS uses peer PID and
UID credentials. The socket is 0600 inside a 0700 directory. Second, scoped
delegation proves that the enrolled agent authorized this delegated key for
this hub and this validity window. A same-user process is not admitted merely
because it can open the socket.

A stolen bundle can impersonate that principal on the specified hub until
expiry or revocation, receive its hint metadata and exercise its permitted
wake/topic operations. It cannot sign durable history as the enrolled key,
read bodies without separate store/API authority, join another hub, or grant
itself broader namespaces. Treat row IDs, sender IDs and body digests as
sensitive metadata despite the absence of message content.

There is no flag that disables verification: a missing or stale authority
source denies admission. The wake carries a SHA-256 **body digest, never a
body**. Under the metadata size ceiling, optional sender, namespace and digest
fields may be shed; row ID and sequence watermark are retained or the hint is
refused. The hub's certification stance is transport-only / NOT-COVERED;
removal must affect latency only, never durable correctness. Read the
[wake-plane reference](wake-hub.md) for the detailed boundary and removal proof.

## 8. Degraded modes

Correctness here means a committed row remains available through normal
storage and retention rules. Delivery still requires an authorized receiver
that resumes reading; a wake is not an acknowledgement or an indefinite
retention promise.

| Condition | What the operator sees | Recovery and durable correctness |
|---|---|---|
| Hub down | Connection failures, reconnect backoff, `backstop` reads | Restore hub; the bounded poll reads committed rows meanwhile. |
| Snapshot stale past its 60-second ceiling | Unauthorized joins, disconnected sessions; posture reports stale snapshot | Restore the refresher with the full retained set. Admission fails closed; inbox reads still work. |
| Slow consumer | Queue/drop/lag counters, disconnects or coalesced pending hints | Catch up once on lag, sequence gap or reconnect, then resume bounded reads. Dropped hints do not delete rows. |
| Hung exec hook | Listener logs timeout and kills the hook after 30 seconds | Repair the hook and use a separate worker; the listener resumes. A hook failure does not acknowledge business work. |
| Unreachable recipient | Pending hints are coalesced and bounded; sender has a storage receipt, no processing receipt | Recipient reconciles on reconnect or polling. Alert on prolonged absence and retention expiry. |

Use read-only checks in the same configured environment:

```bash
ai-memory wake-hub --posture --json
ai-memory wake-hub --health --json
ai-memory doctor
```

A health probe proves socket reachability, not successful delegation, a working
forwarder, or message processing. Verify end to end by sending an HTTP notify
and matching its receipt ID to the recipient's inbox row.

## 9. Troubleshooting

These failures were observed during production deployment. Values below are
placeholders; never copy an operator's keys or deployment coordinates.

| Symptom | Cause and fix |
|---|---|
| `deferred-audit spool ancestor permits untrusted rename` | Store parent directory is not owner-only. Make its dedicated directory 0700 and owned by the service user; inspect the ancestor chain. Do not widen the guard or change shared system directories. |
| `failed to parse private key as RSA, ECDSA, or EdDSA` | macOS LibreSSL `req -newkey ec` can emit explicit EC parameters. Generate with OpenSSL 3 using `-pkeyopt ec_param_enc:named_curve` and PKCS#8, or use RSA/Ed25519. `pkcs8 -topk8` alone does not remove explicit parameters. |
| Non-loopback `serve` refuses despite mTLS | `api_key` in the daemon configuration is independently required. Configure both layers. |
| Local HTTP helper rejected by mTLS | Loopback does not bypass the certificate allowlist. Present a client certificate whose fingerprint is allowed; the daemon's own certificate is a natural local choice when provisioned for that use. |
| Federation `401 peer_not_enrolled` | Certificate pin alone is insufficient. Import the peer's Ed25519 signing public key under its configured peer identity as well. |
| Sender changes after federation | Add the sender to the receiving peer's `allowed_sender_agent_ids`; retain namespace-scoped attestation checks. |
| Local hub returns `404 no such agent` for a remote recipient | Notify fires the local sink even when the agent lives elsewhere. The sink logs a connection failure and reconnects. Durable delivery is unaffected; tracked in [#3635](https://github.com/alphaonedev/ai-memory-mcp/issues/3635). Do not chase it as data loss. |
| Transient federation push failure immediately after daemon restart | Observed delivery recovers through DLQ replay on its next sweep: degrade-never-lose for queued committed delivery. Check replay success and receipt IDs instead of resending blindly. |
| Hub reachable, listener unauthorized | Check matching hub ID, enrolled key, bundle ownership/mode/expiry and fresh allowlist; renew as in section 3. Never disable verification. |
| Inbox rows arrive but no hints | Check `sink_socket`, producer enrolment, snapshot refresh, use of the daemon send surface, and the cross-host limitation in #3631. Polling remains required. |
| Shell agent reruns the same task | Inbox listings are not acknowledgements; persist row-ID deduplication and commit it only after successful processing. |

For example, generate a fresh named-curve key with the OpenSSL 3 executable
selected as `OPENSSL3` (then issue the certificate through your normal CA):

```bash
"$OPENSSL3" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -pkeyopt ec_param_enc:named_curve -out "$NEW_TLS_KEY"
```

Continue with the [CLI reference](CLI_REFERENCE.md),
[messaging atlas](a2a-messaging.html), and
[protocol home](https://alphaonedev.github.io/rust-a2a/).
