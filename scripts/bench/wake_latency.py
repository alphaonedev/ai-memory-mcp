#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""wake_latency.py -- the #3473 wake-plane acceptance instrument.

Issue [#3473] is the acceptance leg of EPIC [#3466]: wake latency p50/p99 at
128 and 256 agents, `ai-memory wake-hub` versus `GET /api/v1/inbox/stream`,
on f2 and f1. This file is that instrument.

What it measures
----------------

For every `memory_notify` it drives, it records the time from **the notify
call returning** -- i.e. the durable inbox row has committed and the substrate
has said so -- to:

  * **hub arm**: the `wake` frame arriving on this recipient's authenticated
    session on the hub's Unix-domain socket;
  * **sse arm**: the `agent_notified` frame arriving on this recipient's
    `GET /api/v1/inbox/stream` subscription.

Both arms are stamped in the SAME place -- in the subscriber thread, straight
after the frame is decoded -- so the comparison cannot be biased by where the
clock is read. Both run against the SAME notify, so the two arms see the same
substrate, the same row and the same instant of commit; a run that measured
them separately would be comparing two different load conditions and calling
the difference a transport.

`t0` is the notify RESPONSE, not the request. That is the honest zero: the
plane's promise starts at "the row is durable", and putting the request send
in the measurement would fold the substrate's own write cost into a number
that is supposed to be about the wake.

What it refuses to do
---------------------

* **It never invents a sample.** A notify that did not return `201` is an
  ERROR, counted and named, never a latency. A wake that never arrived is
  `missing`, counted and named, never folded into a percentile. `#2921`'s rule
  ("an unproduced number is not data") applies to a latency exactly as it does
  to a throughput: a failed request has no latency.
* **A quantile with no observations behind it is `null`, never `0`.** That is
  the same rule `wake_hub::metrics` applies to its own histograms: "no traffic
  yet" and "instantaneous" are different facts and an operator must be able to
  tell them apart. This deliberately differs from `benchlib.percentiles`,
  which returns `0.0` for an empty sample; the conversion happens here, once,
  in `summarise`.
* **It adds no unencrypted listener and offers no `--insecure`.** An `https`
  base URL REQUIRES a pinned `--tls-ca`; a plaintext `http` base URL is
  refused unless the operator names it explicitly with
  `--allow-plaintext-loopback`, and the choice is recorded in the results so a
  number produced over plaintext is never mistaken for one produced over the
  shipped posture.
* **It speaks the tree's own wire format.** The hub client is
  `sdk/python/ai_memory/wake.py`, loaded from this checkout -- not a private
  copy of the codec. A second implementation of a frame parser is a second
  thing that can silently disagree with the hub.

The f1 host effects, reported separately and NEVER folded in
------------------------------------------------------------

Two measured effects on the f1 (macOS) host would otherwise contaminate every
percentile:

  1. the FIRST loopback HTTP round-trip in a fresh process can take >10 s;
  2. a freshly built binary stalls ~48 s at 0 % CPU on its first exec.

(1) is handled here: every HTTP session this harness opens issues a discarded
warm-up request to `/api/v1/health` BEFORE the timed window, and the warm-up
timings are published under `meta.warmup` as their own facts. (2) belongs to
whatever starts the binary; `wake_abab.sh` and `wake_hub_kill.sh` pre-warm it
once and record that separately. Neither is ever subtracted from, averaged
into, or silently hidden inside a percentile: they are host facts about f1,
and a number that quietly absorbed them would be a claim about the substrate
that the substrate did not make.

Subcommands
-----------

  run          the latency measurement (one or more agent counts)
  rate         write-path (`notify`) / read-path (`inbox`) throughput for one
               A-B-A-B leg (alias: `notify-rate`)
  preflight    refuse the hub-kill drill unless every recipient inbox is
               empty (the read path caps at 500 rows with no cursor, so a
               reused database can only ever answer INCONCLUSIVE)
  reconcile    prove no inbox row was lost, from a committed-id ledger
  --self-test  contract checks that need no daemon (alias: --dry-run)

See `scripts/bench/README.md` for the full #3473 procedure.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import resource
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE))

from benchlib import host_facts, percentiles, utc_stamp  # noqa: E402

#: `wake_sink::BACKSTOP_POLL_MAX` -- the normative ceiling on how long a
#: client may go without reading its inbox. Nothing here may wait longer.
BACKSTOP_POLL_MAX = 60.0

#: `wake_hub::DEFAULT_HUB_ID`.
DEFAULT_HUB_ID = "ai-memory-wake-hub"

#: The SSE `event:` name `handlers::inbox_stream` emits per committed notify.
SSE_WAKE_EVENT = "agent_notified"

#: `wake_hub::limits::DESIRED_NOFILE`. Mirrored, not re-derived: macOS ships a
#: soft `RLIMIT_NOFILE` of 256, which is EXACTLY the agent count this
#: instrument has to reach, and an instrument that dies of `EMFILE` at the
#: design target reports nothing at all.
DESIRED_NOFILE = 4096

#: Descriptors this process needs that are not per-agent sockets.
FD_HEADROOM = 64

#: `GET /api/v1/inbox` caps `limit` at 500 server-side and exposes no cursor.
#: A reconciliation that read a truncated inbox could not prove anything, so
#: `reconcile` REFUSES to conclude rather than report a loss it cannot
#: distinguish from a page boundary.
INBOX_LIMIT_CAP = 500

HEALTH_PATH = "/api/v1/health"
NOTIFY_PATH = "/api/v1/notify"
INBOX_PATH = "/api/v1/inbox"
INBOX_STREAM_PATH = "/api/v1/inbox/stream"


#: Overall wall-clock bound on tearing an arm down, NOT a per-thread bound.
TEARDOWN_DEADLINE_SECS = 30.0


class HarnessError(Exception):
    """A refusal. Every one of these is fail-closed: the run stops."""


def _join_bounded(threads: list, deadline_secs: float, what: str) -> None:
    """Join `threads` under ONE deadline shared across all of them."""
    deadline = time.monotonic() + deadline_secs
    for thread in threads:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        thread.join(timeout=remaining)
    alive = sum(1 for t in threads if t.is_alive())
    if alive:
        print(f"[wake_latency] {alive}/{len(threads)} {what} threads outlived the "
              f"{deadline_secs}s teardown deadline; they are daemon threads and "
              f"hold no durable state, so the run continues", file=sys.stderr)


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------


def _tls_context(ca_path: str) -> ssl.SSLContext:
    """A pinned TLS context. Hostname checking stays ON, deliberately.

    The bench daemon's certificate is minted for `127.0.0.1` into the run
    directory (see `wake_abab.sh`), so pinning its own CA is strictly
    stronger than the platform trust store and costs nothing. There is no
    flag that turns verification off: the reason `ai-memory wake-hub` has no
    `--insecure` is the reason this has none either.
    """
    ctx = ssl.create_default_context(cafile=ca_path)
    ctx.check_hostname = True
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class Session:
    """One keep-alive HTTP/1.1 connection to one daemon, TLS or plaintext.

    Deliberately NOT `benchlib.HttpSession`: that class refuses any scheme but
    `http` (its mesh runs on a private single-host bridge). Extending it in
    place would change an instrument three other producers are already
    calibrated against, so this is a sibling with the same shape -- one
    connection per worker, one reconnect, `status == 0` for a request that
    never produced a response -- plus TLS and the warm-up discard #3473 needs.

    Not thread-safe, by the same design: one worker owns one session, so
    "N concurrent" means N real connections rather than N threads contending
    for one socket.
    """

    def __init__(self, base_url: str, agent_id: str | None = None,
                 api_key: str | None = None, tls_ca: str | None = None,
                 allow_plaintext: bool = False, timeout: float = 30.0):
        u = urllib.parse.urlsplit(base_url)
        if u.scheme == "https":
            if not tls_ca:
                raise HarnessError(
                    "an https base URL requires --tls-ca <pem>: this harness pins the "
                    "daemon's own CA rather than trusting whatever the platform store "
                    "holds, and it offers no way to skip verification"
                )
            self.tls: ssl.SSLContext | None = _tls_context(tls_ca)
            default_port = 443
        elif u.scheme == "http":
            if not allow_plaintext:
                raise HarnessError(
                    "refusing a plaintext http base URL. Serve the bench daemon with "
                    "--tls-cert/--tls-key and pass --tls-ca, or state the exception "
                    "explicitly with --allow-plaintext-loopback (it is recorded in the "
                    "results, so a plaintext number is never mistaken for a TLS one)"
                )
            self.tls = None
            default_port = 80
        else:
            raise HarnessError(f"unsupported base URL scheme {u.scheme!r}")
        if not u.hostname:
            raise HarnessError(f"base URL {base_url!r} names no host")
        self.scheme = u.scheme
        self.host = u.hostname
        self.port = u.port or default_port
        self.agent_id = agent_id
        self.api_key = api_key
        self.timeout = timeout
        self._conn: http.client.HTTPConnection | None = None
        #: Elapsed ms of this session's discarded warm-up request, or None.
        self.warmup_ms: float | None = None

    def _connect(self) -> http.client.HTTPConnection:
        if self._conn is None:
            if self.tls is not None:
                self._conn = http.client.HTTPSConnection(
                    self.host, self.port, timeout=self.timeout, context=self.tls)
            else:
                self._conn = http.client.HTTPConnection(
                    self.host, self.port, timeout=self.timeout)
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None

    def set_agent_id(self, agent_id: str) -> None:
        """Re-point this session's `X-Agent-Id` without reconnecting.

        The daemon resolves the caller PER REQUEST from the header, so one
        keep-alive connection can read N agents' inboxes in turn. That is
        what makes the `preflight` and `reconcile` sweeps one handshake
        instead of N — at 256 agents the difference is 256 TLS handshakes
        and 256 discarded warm-ups, which on this host is minutes.

        Only ever used on READ sweeps that are outside a timed window.
        """
        self.agent_id = agent_id

    def headers(self, extra: dict | None = None) -> dict:
        h = {"accept": "application/json"}
        if self.api_key:
            h["x-api-key"] = self.api_key
        if self.agent_id:
            h["x-agent-id"] = self.agent_id
        if extra:
            h.update(extra)
        return h

    def request(self, method: str, path: str,
                body: dict | None = None) -> tuple[int, bytes, float]:
        """Return `(status, body_bytes, elapsed_ms)`.

        `status == 0` means no HTTP response was produced (the connection
        failed twice). It is an error, never a latency.
        """
        payload = None
        headers = self.headers()
        if body is not None:
            payload = json.dumps(body).encode()
            headers["content-type"] = "application/json"
        for attempt in (0, 1):
            conn = self._connect()
            t0 = time.perf_counter()
            try:
                conn.request(method, path, body=payload, headers=headers)
                resp = conn.getresponse()
                data = resp.read()
                return resp.status, data, (time.perf_counter() - t0) * 1000.0
            except (http.client.HTTPException, OSError):
                self.close()
                if attempt == 1:
                    return 0, b"", (time.perf_counter() - t0) * 1000.0
        return 0, b"", 0.0  # unreachable; keeps type checkers honest

    def warmup(self) -> float:
        """Issue and DISCARD this session's first request.

        On f1 the first loopback round-trip in a fresh process has been
        measured above 10 s. Folding that into a p99 would report a host
        start-up effect as a substrate latency, and folding it into a p50 at
        low sample counts would move the headline number. So every session
        spends it here, before the timed window, and the cost is published
        under `meta.warmup` as its own fact.
        """
        status, _, ms = self.request("GET", HEALTH_PATH)
        if status != 200:
            raise HarnessError(
                f"warm-up GET {HEALTH_PATH} returned {status}; refusing to measure "
                "against a daemon that is not serving"
            )
        self.warmup_ms = ms
        return ms


# ---------------------------------------------------------------------------
# file-descriptor budget
# ---------------------------------------------------------------------------


def ensure_fd_budget(required: int) -> dict:
    """Raise this process's soft `RLIMIT_NOFILE`, or REFUSE to run.

    The same posture `wake_hub::startup` takes: size the run from the budget
    actually obtained, and refuse to start when it cannot cover what was
    asked for. An instrument that starts anyway and dies of `EMFILE` half way
    through a 256-agent ramp publishes a truncated sample that looks like a
    completed one.
    """
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    target = min(DESIRED_NOFILE, hard) if hard != resource.RLIM_INFINITY else DESIRED_NOFILE
    obtained = soft
    if soft < target:
        for candidate in (target, 10240, 4096, 2048, 1024):
            if candidate <= soft:
                break
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (candidate, hard))
                obtained = candidate
                break
            except (ValueError, OSError):
                continue
    if obtained < required:
        raise HarnessError(
            f"this run needs {required} file descriptors and this process could only "
            f"obtain {obtained} (soft was {soft}). macOS ships a soft RLIMIT_NOFILE of "
            "256, which is exactly the agent count #3466 designs for; raise it "
            "(`ulimit -n 4096`) rather than running a ramp that would die of EMFILE "
            "mid-sample."
        )
    return {"soft_before": soft, "soft_obtained": obtained, "required": required,
            "desired_nofile": DESIRED_NOFILE}


# ---------------------------------------------------------------------------
# arm 1 -- the hub, over the tree's own client
# ---------------------------------------------------------------------------


def load_sdk_wake(repo: Path):
    """Load `sdk/python/ai_memory/wake.py` as a standalone module.

    Imported BY PATH, not as `ai_memory.wake`: the package `__init__` pulls in
    `httpx` and `pydantic`, and this harness is stdlib-only by the same rule
    `benchlib` is ("a capacity producer whose numbers depend on a pip
    resolution is not reproducible on the host an operator actually has").
    The module itself imports nothing outside the stdlib except `cryptography`
    for Ed25519, which the delegation bundle genuinely needs.

    Using the SHIPPED client is the point: a private copy of the frame codec
    is a second thing that can disagree with the hub, and a disagreement would
    surface as "the hub is slow" rather than as "the harness is wrong".
    """
    import importlib.util

    path = repo / "sdk" / "python" / "ai_memory" / "wake.py"
    if not path.is_file():
        raise HarnessError(
            f"{path} is missing: this harness drives the hub with the tree's own "
            "client and will not substitute a private copy of the wire format"
        )
    spec = importlib.util.spec_from_file_location("ai_memory_wake_3473", path)
    if spec is None or spec.loader is None:
        raise HarnessError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HubArm:
    """N authenticated hub sessions, each stamping its own wake arrivals.

    One OS thread per agent, each running the SDK's `WakeListener`. The
    listener's own reconnect ladder and always-armed backstop stay ON: this
    harness measures the plane as a client actually runs it, and a client that
    disabled the backstop would not be the shipped one.
    """

    def __init__(self, wake_mod, socket_path: str, bundle_dir: str,
                 agents: list[str], hub_id: str):
        self.wake = wake_mod
        self.socket_path = socket_path
        self.bundle_dir = Path(bundle_dir)
        self.agents = agents
        self.hub_id = hub_id
        self.stop = threading.Event()
        self.threads: list[threading.Thread] = []
        self.listeners: dict[str, object] = {}
        self.welcomed = threading.Semaphore(0)
        self._lock = threading.Lock()
        #: inbox_row_id -> perf_counter at frame decode.
        self.arrivals: dict[str, float] = {}
        #: reason -> count, so a run delivered by the BACKSTOP rather than by
        #: the hub can never be reported as a hub latency.
        self.reasons: dict[str, int] = {}

    def _on_signal(self, agent: str, signal) -> None:
        stamp = time.perf_counter()
        reason = str(signal.reason.value)
        with self._lock:
            self.reasons[reason] = self.reasons.get(reason, 0) + 1
            if signal.meta is not None:
                # First arrival wins: a duplicate hint for a row already seen
                # is a re-delivery, and taking the later stamp would report a
                # latency this recipient did not experience.
                self.arrivals.setdefault(signal.meta.inbox_row_id, stamp)
        if reason in ("welcome", "lagged"):
            self.welcomed.release()

    def start(self, ready_timeout: float = 30.0) -> None:
        wake = self.wake
        for agent in self.agents:
            bundle_path = self.bundle_dir / f"{agent}.a2a-hub.json"
            try:
                bundle = wake.DelegationBundle.load(bundle_path, hub_id=self.hub_id)
            except Exception as exc:  # noqa: BLE001 - every load failure is one refusal
                raise HarnessError(
                    f"{agent}: could not load {bundle_path}: {exc}. Mint it with "
                    "`ai-memory identity delegate --scope a2a-hub`."
                ) from exc
            listener = wake.WakeListener(
                self.socket_path, bundle,
                (lambda a: (lambda sig: self._on_signal(a, sig)))(agent),
                poll_interval=BACKSTOP_POLL_MAX,
            )
            self.listeners[agent] = listener
            thread = threading.Thread(
                target=listener.run, args=(self.stop,),
                name=f"hub-{agent}", daemon=True)
            thread.start()
            self.threads.append(thread)
        # FAIL CLOSED on admission. `WakeListener.run` turns every failure into
        # a backoff, which is right for a fleet and wrong for an instrument: a
        # run whose credentials were all refused would otherwise report
        # "0 wakes delivered" and look like a hub defect.
        deadline = time.monotonic() + ready_timeout
        for _ in self.agents:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self.welcomed.acquire(timeout=remaining):
                errors = sorted({str(getattr(x, "last_error", None))
                                 for x in self.listeners.values()
                                 if getattr(x, "last_error", None)})
                raise HarnessError(
                    f"only some of {len(self.agents)} hub sessions were welcomed within "
                    f"{ready_timeout}s; last errors: {errors or ['none reported']}"
                )

    def stop_all(self, deadline_secs: float = TEARDOWN_DEADLINE_SECS) -> None:
        """Stop every listener under ONE overall deadline.

        A per-thread `join(5s)` is a per-thread bound, not a run bound: at
        256 agents a pathological teardown is 256 x 5 s = 21 minutes of a
        driver script appearing to hang between legs. The listeners are
        daemon threads and hold no durable state — the inbox row is the
        record — so a residual is reported and abandoned, never waited on.
        """
        self.stop.set()
        _join_bounded(self.threads, deadline_secs, "hub listener")

    def metrics(self) -> dict:
        totals = {"sessions": 0, "reconnects": 0, "signals": 0}
        for listener in self.listeners.values():
            for key in totals:
                totals[key] += int(getattr(listener, "metrics", {}).get(key, 0))
        return {"listener_totals": totals, "signal_reasons": dict(self.reasons)}


# ---------------------------------------------------------------------------
# arm 2 -- GET /api/v1/inbox/stream (the poll-only comparison arm)
# ---------------------------------------------------------------------------


class SseArm:
    """N long-lived `GET /api/v1/inbox/stream` subscriptions.

    Readiness is the RESPONSE HEADER, and that is a real proof rather than a
    convenience: `handlers::inbox_sse` calls `inbox_wake::subscribe()` while
    building the response, so a `200` in hand means this agent's broadcast
    subscription already exists. Waiting for the first keepalive instead would
    cost 15 s per ramp and prove nothing extra.
    """

    def __init__(self, base_url: str, agents: list[str], tls_ca: str | None,
                 allow_plaintext: bool, api_key: str | None):
        self.base_url = base_url
        self.agents = agents
        self.tls_ca = tls_ca
        self.allow_plaintext = allow_plaintext
        self.api_key = api_key
        self.stop = threading.Event()
        self.threads: list[threading.Thread] = []
        self.sessions: list[Session] = []
        self.opened = threading.Semaphore(0)
        self.open_errors: list[str] = []
        self._lock = threading.Lock()
        self.arrivals: dict[str, float] = {}
        self.events: dict[str, int] = {}

    def _reader(self, agent: str) -> None:
        session = Session(self.base_url, agent_id=agent, api_key=self.api_key,
                          tls_ca=self.tls_ca, allow_plaintext=self.allow_plaintext,
                          timeout=BACKSTOP_POLL_MAX + 30.0)
        with self._lock:
            self.sessions.append(session)
        try:
            session.warmup()
            conn = session._connect()  # noqa: SLF001 - the stream needs the raw response
            conn.request("GET", INBOX_STREAM_PATH,
                         headers=session.headers({"accept": "text/event-stream"}))
            resp = conn.getresponse()
            if resp.status != 200:
                raise HarnessError(
                    f"{agent}: {INBOX_STREAM_PATH} returned {resp.status}; the stream "
                    "was never subscribed, so this arm would report a silence it "
                    "caused itself"
                )
        except Exception as exc:  # noqa: BLE001 - one refusal, reported once
            with self._lock:
                self.open_errors.append(f"{agent}: {exc}")
            self.opened.release()
            return
        self.opened.release()
        buf = b""
        while not self.stop.is_set():
            try:
                chunk = resp.read1(65536)
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                break
            if not chunk:
                break
            stamp = time.perf_counter()
            buf += chunk
            while b"\n\n" in buf:
                block, buf = buf.split(b"\n\n", 1)
                self._on_block(block, stamp)
        try:
            resp.close()
        except OSError:
            pass
        session.close()

    def _on_block(self, block: bytes, stamp: float) -> None:
        name = ""
        data = ""
        for line in block.split(b"\n"):
            line = line.rstrip(b"\r")
            if line.startswith(b":") or not line:
                continue  # keepalive comment
            if line.startswith(b"event:"):
                name = line[6:].strip().decode("utf-8", "replace")
            elif line.startswith(b"data:"):
                data += line[5:].strip().decode("utf-8", "replace")
        if not name:
            return
        with self._lock:
            self.events[name] = self.events.get(name, 0) + 1
        if name != SSE_WAKE_EVENT:
            return
        try:
            payload = json.loads(data)
        except json.JSONDecodeError:
            return
        row_id = payload.get("inbox_row_id")
        if isinstance(row_id, str) and row_id:
            with self._lock:
                self.arrivals.setdefault(row_id, stamp)

    def start(self, ready_timeout: float = 60.0) -> None:
        for agent in self.agents:
            thread = threading.Thread(target=self._reader, args=(agent,),
                                      name=f"sse-{agent}", daemon=True)
            thread.start()
            self.threads.append(thread)
        deadline = time.monotonic() + ready_timeout
        for _ in self.agents:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self.opened.acquire(timeout=remaining):
                raise HarnessError(
                    f"only some of {len(self.agents)} SSE streams opened within "
                    f"{ready_timeout}s"
                )
        if self.open_errors:
            raise HarnessError("SSE arm refused: " + "; ".join(self.open_errors[:5]))

    def stop_all(self, deadline_secs: float = TEARDOWN_DEADLINE_SECS) -> None:
        """Close the streams, then join under ONE overall deadline (A4)."""
        self.stop.set()
        for session in self.sessions:
            session.close()
        _join_bounded(self.threads, deadline_secs, "SSE reader")

    def metrics(self) -> dict:
        return {"events": dict(self.events)}


# ---------------------------------------------------------------------------
# reducers
# ---------------------------------------------------------------------------


def summarise(samples: list[float]) -> dict:
    """p50/p95/p99/max over a latency sample, in milliseconds.

    Percentiles come from `benchlib.percentiles` -- the same nearest-rank
    index arithmetic every other producer in this directory uses, so a figure
    here is directly comparable to one there. The one deliberate difference:
    an EMPTY sample reports `null`, not `0.0`. `wake_hub::metrics` reports a
    quantile with no observations as `null` for the same reason -- "nothing
    was measured" and "it took no time" are different facts, and an alert rule
    (or an acceptance decision) must be able to tell them apart.
    """
    if not samples:
        return {"count": 0, "p50_ms": None, "p95_ms": None, "p99_ms": None,
                "max_ms": None, "mean_ms": None}
    p = percentiles(samples, ps=(50, 95, 99))
    return {
        "count": len(samples),
        "p50_ms": p["p50_ms"],
        "p95_ms": p["p95_ms"],
        "p99_ms": p["p99_ms"],
        "max_ms": round(max(samples), 3),
        "mean_ms": round(sum(samples) / len(samples), 3),
    }


def join_arm(committed: list[dict], arrivals: dict[str, float]) -> dict:
    """Turn `(commit stamp, arrival stamp)` pairs into an arm result.

    A row with no arrival is `missing`: counted, never imputed and never
    dropped silently. A negative delta is impossible here (both stamps come
    from one process's `perf_counter`), so one would mean a bug in this file
    rather than a fast hub -- it is counted separately instead of being
    clamped into a plausible-looking zero.
    """
    deltas: list[float] = []
    missing = 0
    negative = 0
    for row in committed:
        arrival = arrivals.get(row["id"])
        if arrival is None:
            missing += 1
            continue
        delta_ms = (arrival - row["t0"]) * 1000.0
        if delta_ms < 0:
            negative += 1
            continue
        deltas.append(delta_ms)
    out = summarise(deltas)
    out.update({
        "offered": len(committed),
        "delivered": len(deltas),
        "missing": missing,
        "negative_delta": negative,
        "complete": missing == 0 and negative == 0,
    })
    return out


# ---------------------------------------------------------------------------
# the producer
# ---------------------------------------------------------------------------


def drive_notifies(session: Session, sender: str, agents: list[str], count: int,
                   pace_ms: float, duration_secs: float | None,
                   title: str) -> tuple[list[dict], list[dict]]:
    """Offer `count` notifies round-robin across `agents`, paced.

    PACED and single-connection on purpose. #3473 asks for a wake LATENCY, so
    the producer must not be the queue: a saturating driver would measure the
    substrate's admission control and call the result a wake latency. Throughput
    under load is `notify-rate`'s question, and it is asked separately.
    """
    committed: list[dict] = []
    errors: list[dict] = []
    started = time.perf_counter()
    for index in range(count):
        if duration_secs is not None and time.perf_counter() - started >= duration_secs:
            break
        target = agents[index % len(agents)]
        body = {
            "target_agent_id": target,
            "title": title,
            "payload": f"{title} seq={index} target={target}",
        }
        status, data, _ = session.request("POST", NOTIFY_PATH, body=body)
        stamp = time.perf_counter()
        if status != 201:
            errors.append({"seq": index, "target": target, "status": status,
                           "body": data[:200].decode("utf-8", "replace")})
            continue
        try:
            row_id = json.loads(data).get("id")
        except json.JSONDecodeError:
            row_id = None
        if not isinstance(row_id, str) or not row_id:
            errors.append({"seq": index, "target": target, "status": status,
                           "body": "receipt carried no id"})
            continue
        committed.append({"id": row_id, "recipient": target, "t0": stamp, "seq": index})
        if pace_ms > 0:
            time.sleep(pace_ms / 1000.0)
    return committed, errors


# ---------------------------------------------------------------------------
# host facts
# ---------------------------------------------------------------------------


def portable_host_facts() -> dict:
    """`benchlib.host_facts()`, with the macOS blanks filled from `sysctl`.

    `benchlib.host_facts` reads `/proc` and `/sys`, so on f1 it returns
    `null` for the CPU model, RAM and storage. Those nulls are honest but
    useless for an acceptance report that has to say which host produced the
    number, so the macOS values are read from `sysctl` -- READ, never guessed.
    A fact that cannot be read stays `null`.
    """
    facts = host_facts()
    if sys.platform != "darwin":
        return facts
    import subprocess

    def sysctl(name: str) -> str | None:
        try:
            out = subprocess.run(["sysctl", "-n", name], capture_output=True,
                                 text=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            return None
        value = out.stdout.strip()
        return value or None

    if facts.get("cpu_model") is None:
        facts["cpu_model"] = sysctl("machdep.cpu.brand_string")
    if facts.get("mem_total_kb") is None:
        mem = sysctl("hw.memsize")
        if mem and mem.isdigit():
            facts["mem_total_kb"] = int(mem) // 1024
            facts["mem_total_gib"] = round(int(mem) / (1024 ** 3), 1)
    facts["os"] = facts.get("os") or f"macOS {os.uname().release}"
    return facts


def transport_meta(base_url: str, tls_ca: str | None, allow_plaintext: bool) -> dict:
    scheme = urllib.parse.urlsplit(base_url).scheme
    return {
        "scheme": scheme,
        "tls": scheme == "https",
        "tls_ca_pinned": bool(tls_ca) and scheme == "https",
        "plaintext_exception_taken": scheme == "http" and allow_plaintext,
        "note": ("A figure produced over plaintext is NOT a figure produced under the "
                 "shipped posture; this field is what tells the two apart."),
    }


# ---------------------------------------------------------------------------
# cmd: run
# ---------------------------------------------------------------------------


def cmd_run(a: argparse.Namespace) -> int:
    agent_counts = [int(x) for x in a.agents.split()]
    arms = [x.strip() for x in a.arms.split(",") if x.strip()]
    for arm in arms:
        if arm not in ("hub", "sse"):
            raise HarnessError(f"unknown arm {arm!r}: expected hub and/or sse")
    if "hub" in arms and not (a.hub_socket and a.bundle_dir):
        raise HarnessError("--arms hub requires --hub-socket and --bundle-dir")

    max_agents = max(agent_counts)
    fds = ensure_fd_budget(max_agents * len(arms) + FD_HEADROOM + 8)

    wake_mod = load_sdk_wake(REPO) if "hub" in arms else None
    # A smaller thread stack, because 256 agents x 2 arms is 512 threads and
    # the default 8 MiB reservation is a lot of address space for a stack that
    # holds one frame parser.
    threading.stack_size(512 * 1024)

    producer = Session(a.base_url, agent_id=a.sender, api_key=a.api_key,
                       tls_ca=a.tls_ca, allow_plaintext=a.allow_plaintext_loopback)
    warm_ms = producer.warmup()
    points = []
    committed_ledger: list[dict] = []
    t_start = time.time()

    for count in agent_counts:
        agents = [a.agent_template.format(i=i) for i in range(count)]
        hub_arm = None
        sse_arm = None
        try:
            if "hub" in arms:
                hub_arm = HubArm(wake_mod, a.hub_socket, a.bundle_dir, agents, a.hub_id)
                hub_arm.start(ready_timeout=a.ready_timeout)
            if "sse" in arms:
                sse_arm = SseArm(a.base_url, agents, a.tls_ca,
                                 a.allow_plaintext_loopback, a.api_key)
                sse_arm.start(ready_timeout=a.ready_timeout)
            # Both arms are attached BEFORE the first timed notify. A wake
            # minted for a recipient that had not yet subscribed is not a slow
            # wake, it is an absent one, and counting it as either would be
            # wrong.
            #
            # The readiness FILE is what lets a driver script time an event
            # against the producer -- `wake_hub_kill.sh` needs its SIGKILL to
            # land while notifies are in flight, and "sleep and hope the
            # attach finished" is not a schedule, it is a race whose outcome
            # decides whether the drill tested anything.
            if a.ready_file:
                Path(a.ready_file).write_text(
                    json.dumps({"agents": count, "arms": arms,
                                "ready_at_utc": utc_stamp()}) + "\n",
                    encoding="utf-8")
            committed, errors = drive_notifies(
                producer, a.sender, agents, a.notifies, a.pace_ms,
                a.duration_secs, a.title)
            # Let the tail land. The settle window is bounded and reported: a
            # wake that needed longer than this is `missing`, which is the
            # honest description of what an operator would have observed.
            time.sleep(a.settle_secs)
            point = {
                "agents": count,
                "offered": len(committed),
                "notify_errors": len(errors),
                "notify_error_sample": errors[:5],
                "pace_ms": a.pace_ms,
                "arms": {},
            }
            if hub_arm is not None:
                point["arms"]["hub"] = join_arm(committed, dict(hub_arm.arrivals))
                point["arms"]["hub"].update(hub_arm.metrics())
            if sse_arm is not None:
                point["arms"]["sse"] = join_arm(committed, dict(sse_arm.arrivals))
                point["arms"]["sse"].update(sse_arm.metrics())
            points.append(point)
            committed_ledger.extend(committed)
        finally:
            if sse_arm is not None:
                sse_arm.stop_all()
            if hub_arm is not None:
                hub_arm.stop_all()

    producer.close()

    out = {
        "meta": {
            "issue": 3473,
            "epic": 3466,
            "producer": "scripts/bench/wake_latency.py",
            "producer_argv": sys.argv[1:],
            "label": a.label,
            "backend": a.backend,
            "host_substrate": a.host_substrate,
            "generated_at_utc": utc_stamp(),
            "measured_label": "MEASURED",
            "t0_definition": ("the notify HTTP response (the durable inbox row has "
                              "committed), NOT the request"),
            "arms": arms,
            "hub_id": a.hub_id if "hub" in arms else None,
            "transport": transport_meta(a.base_url, a.tls_ca,
                                        a.allow_plaintext_loopback),
            "fd_budget": fds,
            "warmup": {
                "producer_first_request_ms": round(warm_ms, 3),
                "note": ("DISCARDED, never folded into a percentile. On f1 the first "
                         "loopback round-trip in a fresh process has been measured "
                         "above 10 s; every session this harness opens spends its "
                         "first request here, before the timed window."),
            },
            "settle_secs": a.settle_secs,
            "host_facts": portable_host_facts(),
            "elapsed_wall_secs": round(time.time() - t_start, 2),
        },
        "points": points,
    }
    if a.committed_out:
        with open(a.committed_out, "w", encoding="utf-8") as fh:
            for row in committed_ledger:
                fh.write(json.dumps({"id": row["id"], "recipient": row["recipient"]}) + "\n")
        print(f"[wake_latency] committed ledger -> {a.committed_out}", file=sys.stderr)
    emit(out, a.out)
    print_table(points, arms)
    return 0


def print_table(points: list[dict], arms: list[str]) -> None:
    head = f"{'agents':>7} {'arm':<5} {'n':>6} {'p50':>9} {'p95':>9} {'p99':>9} {'max':>9} {'miss':>6}"
    print(head, file=sys.stderr)
    print("-" * len(head), file=sys.stderr)
    for point in points:
        for arm in arms:
            row = point["arms"].get(arm)
            if row is None:
                continue

            def fmt(value):
                return "null" if value is None else f"{value:.3f}"

            print(f"{point['agents']:>7} {arm:<5} {row['delivered']:>6} "
                  f"{fmt(row['p50_ms']):>9} {fmt(row['p95_ms']):>9} "
                  f"{fmt(row['p99_ms']):>9} {fmt(row['max_ms']):>9} "
                  f"{row['missing']:>6}", file=sys.stderr)


def emit(out: dict, path: str | None) -> None:
    if path:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        print(f"[wake_latency] -> {path}", file=sys.stderr)
    else:
        json.dump(out, sys.stdout, indent=2)
        print()


# ---------------------------------------------------------------------------
# cmd: notify-rate  (the write path the wake sink actually touches)
# ---------------------------------------------------------------------------


#: `ops_producer.py`'s admission-control code. A shed request is counted
#: separately and never as throughput.
SHED_CODE = 503


def cmd_rate(a: argparse.Namespace) -> int:
    """Offered-concurrency throughput + latency for one A-B-A-B leg.

    Why not `ops_producer.py`? Two reasons, and both are structural rather
    than stylistic:

      * `benchlib.HttpSession` refuses any scheme but `http` by construction.
        This lane serves the daemon over TLS and opens no plaintext listener,
        so that instrument cannot reach it -- and widening it would change a
        class three already-calibrated producers depend on.
      * Neither `memory_store` nor `memory_recall` passes through
        `write_events::agent_notified`, which is the emitter the wake sink
        hangs off. A no-regression claim that never exercised the notify path
        would be a claim about code the change did not touch.

    Two ops, and they are the two the wake plane sits on:

      * `notify` -- the WRITE path. Every wake this EPIC exists to deliver is
        minted here, after the row commits.
      * `inbox`  -- the READ path. "Wake, then read once" means the read that
        matters is the inbox read; it also needs no seeded corpus and no
        attested write ceremony, so it measures the same thing on any host.

    `recall` is available for a leg run against an already-seeded corpus. It
    is not the default because an empty corpus would make both legs measure
    the same empty query and call the agreement a result.
    """
    agents = [a.agent_template.format(i=i) for i in range(a.agents)]
    ensure_fd_budget(a.concurrency + FD_HEADROOM)
    threading.stack_size(512 * 1024)

    results: list[dict] = []
    lock = threading.Lock()
    stop_at = time.perf_counter() + a.duration

    def worker(wid: int) -> None:
        # For `notify` the wire identity is the SENDER; for a read the wire
        # identity must be the inbox OWNER, because `get_inbox` resolves the
        # owner from the header and refuses a mismatching query value.
        agent = a.sender if a.op == "notify" else agents[wid % len(agents)]
        session = Session(a.base_url, agent_id=agent, api_key=a.api_key,
                          tls_ca=a.tls_ca,
                          allow_plaintext=a.allow_plaintext_loopback)
        try:
            session.warmup()
        except HarnessError as exc:
            with lock:
                results.append({"worker": wid, "fatal": str(exc)})
            return
        ok = 0
        shed = 0
        errors = 0
        codes: dict[int, int] = {}
        latencies: list[float] = []
        index = wid
        while time.perf_counter() < stop_at:
            target = agents[index % len(agents)]
            index += max(a.concurrency, 1)
            if a.op == "notify":
                status, _, ms = session.request("POST", NOTIFY_PATH, body={
                    "target_agent_id": target,
                    "title": a.title,
                    "payload": f"{a.title} w={wid} i={index}",
                })
            elif a.op == "inbox":
                status, _, ms = session.request(
                    "GET", f"{INBOX_PATH}?agent_id={urllib.parse.quote(agent)}"
                            f"&limit={a.inbox_limit}")
            else:  # recall
                status, _, ms = session.request(
                    "GET", f"/api/v1/recall?q={urllib.parse.quote(a.query)}"
                            f"&namespace={urllib.parse.quote(a.namespace)}&limit=5")
            codes[status] = codes.get(status, 0) + 1
            if status == SHED_CODE:
                shed += 1
            elif 200 <= status < 300:
                ok += 1
                latencies.append(ms)
            else:
                errors += 1
        session.close()
        with lock:
            results.append({"worker": wid, "ok": ok, "shed": shed,
                            "errors": errors, "codes": codes,
                            "latencies": latencies})

    t0 = time.perf_counter()
    threads = [threading.Thread(target=worker, args=(i,), name=f"{a.op}-{i}")
               for i in range(a.concurrency)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    wall = time.perf_counter() - t0

    fatal = [r["fatal"] for r in results if "fatal" in r]
    if fatal:
        raise HarnessError(f"{a.op}-rate could not start: " + "; ".join(fatal[:3]))
    ok = sum(r["ok"] for r in results)
    shed = sum(r["shed"] for r in results)
    errors = sum(r["errors"] for r in results)
    codes: dict[str, int] = {}
    for row in results:
        for status, count in row["codes"].items():
            codes[str(status)] = codes.get(str(status), 0) + count
    latencies = [ms for r in results for ms in r["latencies"]]
    reqs = ok + shed + errors
    out = {
        "meta": {
            "issue": 3473,
            "producer": "scripts/bench/wake_latency.py rate",
            "producer_argv": sys.argv[1:],
            "label": a.label,
            "leg": a.leg,
            "op": a.op,
            "backend": a.backend,
            "host_substrate": a.host_substrate,
            "generated_at_utc": utc_stamp(),
            "measured_label": "MEASURED",
            "transport": transport_meta(a.base_url, a.tls_ca,
                                        a.allow_plaintext_loopback),
            "host_facts": portable_host_facts(),
        },
        "point": {
            "op": a.op,
            "offered_concurrency": a.concurrency,
            "recipient_agents": a.agents,
            "wall_secs": round(wall, 3),
            "reqs": reqs,
            "ok": ok,
            "shed": shed,
            "shed_rate": round(shed / reqs, 4) if reqs else 0.0,
            "errors": errors,
            "status_codes": codes,
            # SUCCEEDED operations only, exactly as `ops_producer.py` counts
            # them. Folding refusals into a rate is how an overloaded daemon
            # reports its best number.
            "total_ops_per_s": round(ok / wall, 4) if wall > 0 else 0.0,
            "latency": summarise(latencies),
        },
    }
    emit(out, a.out)
    print(f"[wake_latency] {a.leg} {a.op}: {out['point']['total_ops_per_s']} ops/s "
          f"(ok={ok} shed={shed} err={errors})", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# cmd: hold  (N attached sessions, for the A-B-A-B "hub on" legs)
# ---------------------------------------------------------------------------


def cmd_hold(a: argparse.Namespace) -> int:
    """Attach N sessions and HOLD them until signalled.

    The `B` legs of the A-B-A-B are not "the hub process is running" -- they
    are "N agents are attached to it". A throughput rung measured against an
    idle hub would answer a question nobody asked: the cost the sink and the
    hub can impose is the cost of fanning a wake out to attached recipients,
    and with nobody attached there is nothing to fan out to.

    Readiness is a FILE, written only after every session has been welcomed,
    so the driver script starts its rung when the load is really in place
    rather than after a sleep that might be too short on a loaded host.
    """
    import signal

    agents = [a.agent_template.format(i=i) for i in range(a.agents)]
    arms = [x.strip() for x in a.arms.split(",") if x.strip()]
    ensure_fd_budget(len(agents) * max(len(arms), 1) + FD_HEADROOM)
    threading.stack_size(512 * 1024)

    hub_arm = None
    sse_arm = None
    if "hub" in arms:
        hub_arm = HubArm(load_sdk_wake(REPO), a.hub_socket, a.bundle_dir,
                         agents, a.hub_id)
        hub_arm.start(ready_timeout=a.ready_timeout)
    if "sse" in arms:
        sse_arm = SseArm(a.base_url, agents, a.tls_ca,
                         a.allow_plaintext_loopback, a.api_key)
        sse_arm.start(ready_timeout=a.ready_timeout)

    done = threading.Event()

    def on_signal(_signum, _frame):
        done.set()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    if a.ready_file:
        Path(a.ready_file).write_text(
            json.dumps({"agents": len(agents), "arms": arms,
                        "ready_at_utc": utc_stamp()}) + "\n", encoding="utf-8")
    print(f"[wake_latency] holding {len(agents)} sessions on {arms}", file=sys.stderr)
    done.wait(timeout=a.max_secs)

    out = {
        "meta": {
            "issue": 3473,
            "producer": "scripts/bench/wake_latency.py hold",
            "producer_argv": sys.argv[1:],
            "label": a.label,
            "generated_at_utc": utc_stamp(),
        },
        "agents": len(agents),
        "arms": arms,
        "hub": hub_arm.metrics() if hub_arm is not None else None,
        "sse": sse_arm.metrics() if sse_arm is not None else None,
    }
    if sse_arm is not None:
        sse_arm.stop_all()
    if hub_arm is not None:
        hub_arm.stop_all()
    emit(out, a.out)
    return 0


# ---------------------------------------------------------------------------
# cmd: reconcile  (no inbox row was lost)
# ---------------------------------------------------------------------------


def read_inbox_ids(session: Session, agent: str, limit: int) -> tuple[set[str], int]:
    status, data, _ = session.request(
        "GET", f"{INBOX_PATH}?agent_id={urllib.parse.quote(agent)}&limit={limit}")
    if status != 200:
        raise HarnessError(f"{agent}: GET {INBOX_PATH} returned {status}")
    payload = json.loads(data)
    messages = payload.get("messages") or []
    ids = {m.get("id") for m in messages if isinstance(m.get("id"), str)}
    return ids, len(messages)


def cmd_preflight(a: argparse.Namespace) -> int:
    """REFUSE to start a hub-kill drill on a database that already has mail.

    The row-loss gate reads each recipient's inbox through
    `GET /api/v1/inbox`, which caps `limit` at 500 SERVER-SIDE and exposes no
    cursor. So a recipient carrying rows from an EARLIER run — the
    `wake_abab.sh` notify legs write thousands to these same ids, and the
    README's own ordering runs them first against the same `--db-name` — will
    hit that ceiling, and a truncated read cannot tell "lost" from "past the
    page". The drill would then report INCONCLUSIVE by construction: never a
    false PASS, but never a usable answer either, after paying for the whole
    run.

    Checking BEFORE the first notify converts that into a refusal that costs
    seconds and names the remedy. It is the load-bearing half of the fix:
    the README can be re-ordered, but only this check can prove the database
    was actually clean for THIS run.
    """
    agents = [a.agent_template.format(i=i) for i in range(a.agents)]
    session = Session(a.base_url, api_key=a.api_key, tls_ca=a.tls_ca,
                      allow_plaintext=a.allow_plaintext_loopback)
    dirty: list[tuple[str, int]] = []
    try:
        session.warmup()
        for agent in agents:
            session.set_agent_id(agent)
            _, returned = read_inbox_ids(session, agent, 1)
            if returned:
                dirty.append((agent, returned))
    finally:
        session.close()

    if dirty:
        sample = ", ".join(f"{name}" for name, _ in dirty[:5])
        more = f" (+{len(dirty) - 5} more)" if len(dirty) > 5 else ""
        raise HarnessError(
            f"{len(dirty)} of {len(agents)} recipient inboxes already carry rows "
            f"— e.g. {sample}{more}. `GET /api/v1/inbox` caps at "
            f"{INBOX_LIMIT_CAP} rows with no cursor, so the hub-kill row-loss "
            "gate could only report INCONCLUSIVE against this database. Run the "
            "drill against a FRESH database (its own --db-name, or DROP and "
            "CREATE between steps); the A-B-A-B notify legs write to these same "
            "recipient ids."
        )
    print(f"[wake_latency] preflight: {len(agents)} recipient inboxes are empty",
          file=sys.stderr)
    return 0


def cmd_reconcile(a: argparse.Namespace) -> int:
    """Prove that every committed notify is still readable through the inbox.

    This is the #3473 hub-kill acceptance: SIGKILL the hub mid-run and no
    inbox row may be lost. The wake plane holds no durable truth, so the
    proof has to come from the durable side -- the ledger of ids the
    substrate ACKNOWLEDGED (`201` + a receipt id) against what
    `GET /api/v1/inbox` returns afterwards.

    Three outcomes, and the third is why this is trustworthy:

      * PASS -- every committed id is present.
      * LOST -- at least one is not. Exit 1. This is a data-integrity
        failure and it is reported as one.
      * INCONCLUSIVE -- an inbox came back at the server's `limit` ceiling,
        so the read may have been truncated. Exit 3. A truncated read cannot
        distinguish "lost" from "past the page", and reporting PASS from one
        would be inventing the guarantee this drill exists to test.
    """
    by_agent: dict[str, set[str]] = {}
    total = 0
    with open(a.committed, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            by_agent.setdefault(row["recipient"], set()).add(row["id"])
            total += 1

    limit = min(a.limit, INBOX_LIMIT_CAP)
    truncated: list[str] = []
    missing: dict[str, list[str]] = {}
    present_total = 0
    # ONE keep-alive connection, re-pointed per recipient: the identity is a
    # per-request header, and 256 handshakes plus 256 warm-ups would cost
    # minutes on this host for no extra evidence.
    session = Session(a.base_url, api_key=a.api_key, tls_ca=a.tls_ca,
                      allow_plaintext=a.allow_plaintext_loopback)
    try:
        session.warmup()
        for agent, expected in sorted(by_agent.items()):
            session.set_agent_id(agent)
            ids, returned = read_inbox_ids(session, agent, limit)
            present_total += returned
            if returned >= limit:
                truncated.append(agent)
            gone = sorted(expected - ids)
            if gone:
                missing[agent] = gone[:20]
    finally:
        session.close()

    verdict = "PASS"
    code = 0
    if missing:
        verdict, code = "LOST", 1
    elif truncated:
        verdict, code = "INCONCLUSIVE", 3

    out = {
        "meta": {
            "issue": 3473,
            "producer": "scripts/bench/wake_latency.py reconcile",
            "producer_argv": sys.argv[1:],
            "label": a.label,
            "generated_at_utc": utc_stamp(),
            "inbox_read_limit": limit,
            "note": ("The wake plane holds no durable truth, so this compares the ids "
                     "the substrate ACKNOWLEDGED against what the inbox read path "
                     "returns. A wake that never arrived costs latency; a row that is "
                     "not here would be loss."),
        },
        "verdict": verdict,
        "committed_rows": total,
        "recipients": len(by_agent),
        "rows_present": present_total,
        "missing_rows": sum(len(v) for v in missing.values()),
        "missing_sample": missing,
        "truncated_inboxes": truncated,
    }
    emit(out, a.out)
    print(f"[wake_latency] reconcile: {verdict} "
          f"({total} committed, {out['missing_rows']} missing)", file=sys.stderr)
    return code


# ---------------------------------------------------------------------------
# self-test
# ---------------------------------------------------------------------------


def self_test() -> int:
    """Contract checks that need no daemon: reducers, refusals, JSON shape."""
    ok = True

    def check(cond, msg):
        nonlocal ok
        if not cond:
            print(f"FAIL: {msg}", file=sys.stderr)
            ok = False

    # 1. Percentile math on a KNOWN vector, through benchlib's nearest-rank
    #    index arithmetic (i = int(p/100 * n), clamped) so a figure here is
    #    comparable to one from ops_producer.py / mesh_probe.py.
    vector = [float(x) for x in range(1, 101)]  # 1.0 .. 100.0
    s = summarise(vector)
    check(s["p50_ms"] == 51.0, f"nearest-rank p50 of 1..100 is 51.0, got {s['p50_ms']}")
    check(s["p95_ms"] == 96.0, f"nearest-rank p95 of 1..100 is 96.0, got {s['p95_ms']}")
    check(s["p99_ms"] == 100.0, f"nearest-rank p99 of 1..100 is 100.0, got {s['p99_ms']}")
    check(s["max_ms"] == 100.0, f"max of 1..100 is 100.0, got {s['max_ms']}")
    check(s["count"] == 100, "count must be the sample size")

    small = summarise([5.0])
    check(small["p50_ms"] == 5.0 and small["p99_ms"] == 5.0,
          "a one-sample vector reports that sample at every quantile")

    # 2. No observations is NOT zero latency (wake_hub::metrics' own rule).
    empty = summarise([])
    check(all(empty[k] is None for k in ("p50_ms", "p95_ms", "p99_ms", "max_ms")),
          "an empty sample must report null quantiles, never 0.0")
    check(empty["count"] == 0, "an empty sample counts zero observations")

    # 3. A missing wake is `missing`, never an imputed latency.
    committed = [{"id": "a", "recipient": "x", "t0": 1.000, "seq": 0},
                 {"id": "b", "recipient": "y", "t0": 2.000, "seq": 1}]
    joined = join_arm(committed, {"a": 1.002})
    check(joined["delivered"] == 1 and joined["missing"] == 1,
          f"one arrival of two is 1 delivered / 1 missing, got {joined}")
    check(abs(joined["p50_ms"] - 2.0) < 1e-6,
          f"a 2 ms delta must reduce to 2.0 ms, got {joined['p50_ms']}")
    check(joined["complete"] is False, "a run with a missing wake is not complete")
    check(join_arm(committed, {})["p99_ms"] is None,
          "an arm that received nothing reports null, not 0.0")
    negative = join_arm([{"id": "a", "recipient": "x", "t0": 5.0, "seq": 0}],
                        {"a": 4.0})
    check(negative["negative_delta"] == 1 and negative["delivered"] == 0,
          "a negative delta is counted as a bug, never clamped to zero")

    # 4. Transport refusals are fail-closed and there is no insecure flag.
    try:
        Session("https://127.0.0.1:9443")
        check(False, "https without --tls-ca must be refused")
    except HarnessError:
        pass
    try:
        Session("http://127.0.0.1:9077")
        check(False, "plaintext http must be refused without the explicit exception")
    except HarnessError:
        pass
    session = Session("http://127.0.0.1:9077", allow_plaintext=True)
    check(session.scheme == "http" and session.tls is None,
          "the named plaintext exception must still produce a usable session")
    # The needles are ASSEMBLED rather than written out, so this assertion
    # cannot match itself and report the check as the violation.
    source = Path(__file__).read_text(encoding="utf-8")
    forbidden = ["CERT_" + "NONE", "check_hostname = " + "False",
                 "verify_mode = " + "ssl.CERT_" + "NONE"]
    check(not any(needle in source for needle in forbidden),
          "this harness must never grow a verification-skipping path")
    check("insecure" not in {act.dest for act in build_parser()._actions},  # noqa: SLF001
          "this harness must never grow a verification-skipping flag")

    meta = transport_meta("http://127.0.0.1:9077", None, True)
    check(meta["plaintext_exception_taken"] is True and meta["tls"] is False,
          "a plaintext run must be labelled as one in the results")
    meta = transport_meta("https://127.0.0.1:9443", "/tmp/ca.pem", False)
    check(meta["tls"] is True and meta["tls_ca_pinned"] is True,
          "a TLS run must record that its CA was pinned")

    # 5. Argument parsing, end to end, for the exact phase-2 command line.
    parser = build_parser()
    args = parser.parse_args([
        "run", "--base-url", "https://127.0.0.1:9443", "--tls-ca", "/x/ca.pem",
        "--agents", "16 64 128 256", "--arms", "hub,sse",
        "--hub-socket", "/x/wake-hub.sock", "--bundle-dir", "/x/bundles",
        "--sender", "ai:bench-sender", "--notifies", "512",
    ])
    check(args.cmd == "run" and args.agents == "16 64 128 256",
          "the agent sweep must parse as a whitespace-separated list")
    check([int(x) for x in args.agents.split()] == [16, 64, 128, 256],
          "the sweep must reduce to the four #3473 rungs")
    check(args.arms == "hub,sse" and args.notifies == 512, "run args must round-trip")
    check(hasattr(args, "ready_file"),
          "`run` must expose --ready-file: wake_hub_kill.sh times its SIGKILL "
          "from the moment the listeners are attached, not from process start")

    args = parser.parse_args([
        "rate", "--op", "inbox", "--base-url", "https://127.0.0.1:9443",
        "--tls-ca", "/x/ca.pem", "--sender", "ai:s", "--leg", "B1",
    ])
    check(args.cmd == "rate" and args.op == "inbox" and args.leg == "B1",
          "the A-B-A-B leg args must round-trip")
    args = parser.parse_args([
        "notify-rate", "--base-url", "https://127.0.0.1:9443",
        "--tls-ca", "/x/ca.pem", "--sender", "ai:s",
    ])
    check(args.op == "notify",
          "the legacy `notify-rate` spelling must still reach the notify op")

    args = parser.parse_args([
        "preflight", "--base-url", "https://127.0.0.1:9443",
        "--tls-ca", "/x/ca.pem", "--agents", "128",
    ])
    check(args.cmd == "preflight" and args.agents == 128,
          "the hub-kill pre-flight must parse an agent count")

    # A session's identity is a per-request header, so one keep-alive
    # connection serves the whole read sweep.
    probe = Session("http://127.0.0.1:9443", agent_id="ai:a", allow_plaintext=True)
    probe.set_agent_id("ai:b")
    check(probe.headers()["x-agent-id"] == "ai:b",
          "set_agent_id must re-point the wire identity without reconnecting")

    # Teardown is bounded OVERALL, not per thread: 256 x 5 s is 21 minutes.
    idle = [threading.Thread(target=lambda: None) for _ in range(3)]
    for t in idle:
        t.start()
    started = time.monotonic()
    _join_bounded(idle, 5.0, "self-test")
    check(time.monotonic() - started < 5.0, "a bounded join must not spend its budget")
    check(TEARDOWN_DEADLINE_SECS == 30.0,
          "the teardown deadline is a RUN bound; a per-thread bound at 256 "
          "agents is a 21-minute hang between legs")

    # 6. The reconcile ceiling is the server's, not a local guess.
    check(SHED_CODE == 503,
          "admission-control shedding must be counted apart from throughput, "
          "on the same code ops_producer.py uses")
    check(INBOX_LIMIT_CAP == 500,
          "GET /api/v1/inbox caps limit at 500 server-side; this must match")

    # 7. Results must not embed a home-directory path (ops_producer's rule).
    facts = portable_host_facts()
    check(facts.get("cpu_logical_cores") is not None,
          "host facts must carry a core count")
    check("/Users/" not in json.dumps(facts) and "/home/" not in json.dumps(facts),
          "host facts must not embed a home-directory path")

    # 8. The normative bounds are mirrored, not invented.
    check(BACKSTOP_POLL_MAX == 60.0, "BACKSTOP_POLL_MAX must be wake_sink's 60 s")
    check(DEFAULT_HUB_ID == "ai-memory-wake-hub", "hub id must match wake_hub's default")
    check(DESIRED_NOFILE == 4096, "fd target must match wake_hub::limits::DESIRED_NOFILE")

    print("wake_latency self-test:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# argv
# ---------------------------------------------------------------------------


def _transport_args(sub: argparse.ArgumentParser) -> None:
    sub.add_argument("--base-url", required=True,
                     help="daemon base URL; https REQUIRES --tls-ca")
    sub.add_argument("--tls-ca", help="PEM the daemon's certificate is pinned to")
    sub.add_argument("--allow-plaintext-loopback", action="store_true",
                     help="explicit, recorded exception for a plaintext http daemon")
    sub.add_argument("--api-key", help="x-api-key, when the daemon requires one")
    sub.add_argument("--label", default="wake-latency-3473")
    sub.add_argument("--backend", default="postgres", choices=("postgres", "sqlite"))
    sub.add_argument("--host-substrate", default="f1")
    sub.add_argument("--out", help="write the results JSON here (default: stdout)")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="See scripts/bench/README.md for the #3473 procedure.")
    ap.add_argument("--self-test", action="store_true",
                    help="contract checks with no daemon (reducers, refusals, argv)")
    ap.add_argument("--dry-run", dest="self_test", action="store_true",
                    help=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="cmd")

    run = sub.add_parser("run", help="wake latency, hub arm vs SSE arm")
    _transport_args(run)
    run.add_argument("--agents", default="16 64 128 256",
                     help="whitespace-separated agent counts to sweep")
    run.add_argument("--arms", default="hub,sse")
    run.add_argument("--hub-socket")
    run.add_argument("--bundle-dir",
                     help="directory of <agent>.a2a-hub.json delegation bundles")
    run.add_argument("--hub-id", default=DEFAULT_HUB_ID)
    run.add_argument("--sender", required=True, help="the notifying agent id")
    run.add_argument("--agent-template", default="ai:wake-bench-{i:04d}")
    run.add_argument("--notifies", type=int, default=512,
                     help="notifies offered per agent-count rung")
    run.add_argument("--duration-secs", type=float,
                     help="stop a rung early after this many seconds")
    run.add_argument("--pace-ms", type=float, default=25.0,
                     help="gap between notifies; this measures latency, not saturation")
    run.add_argument("--settle-secs", type=float, default=5.0,
                     help="bounded wait for the tail; a later wake is `missing`")
    run.add_argument("--ready-timeout", type=float, default=60.0)
    run.add_argument("--title", default="wake-latency-3473")
    run.add_argument("--committed-out",
                     help="NDJSON ledger of committed row ids, for `reconcile`")
    run.add_argument("--ready-file",
                     help="written once the arms are attached and BEFORE the first "
                          "notify, so a driver can time an event against the load")

    rate = sub.add_parser("rate", aliases=["notify-rate"],
                          help="write/read-path throughput for one A-B-A-B leg")
    _transport_args(rate)
    rate.add_argument("--op", default="notify", choices=("notify", "inbox", "recall"))
    rate.add_argument("--sender", required=True)
    rate.add_argument("--agents", type=int, default=128)
    rate.add_argument("--agent-template", default="ai:wake-bench-{i:04d}")
    rate.add_argument("--concurrency", type=int, default=8)
    rate.add_argument("--duration", type=float, default=20.0)
    rate.add_argument("--title", default="wake-abab-3473")
    rate.add_argument("--inbox-limit", type=int, default=20)
    rate.add_argument("--query", default="wake", help="recall op only")
    rate.add_argument("--namespace", default="wake-bench-3473", help="recall op only")
    rate.add_argument("--leg", default="unnamed", help="A1/B1/A2/B2")

    hold = sub.add_parser("hold", help="attach N sessions and hold them until SIGTERM")
    _transport_args(hold)
    hold.add_argument("--agents", type=int, required=True)
    hold.add_argument("--agent-template", default="ai:wake-bench-{i:04d}")
    hold.add_argument("--arms", default="hub")
    hold.add_argument("--hub-socket")
    hold.add_argument("--bundle-dir")
    hold.add_argument("--hub-id", default=DEFAULT_HUB_ID)
    hold.add_argument("--ready-timeout", type=float, default=120.0)
    hold.add_argument("--ready-file",
                      help="written once every session has been welcomed")
    hold.add_argument("--max-secs", type=float, default=3600.0,
                      help="bounded: a held run can never outlive the drill")

    pre = sub.add_parser(
        "preflight",
        help="refuse to start the hub-kill drill unless every recipient inbox is empty")
    _transport_args(pre)
    pre.add_argument("--agents", type=int, required=True)
    pre.add_argument("--agent-template", default="ai:wake-bench-{i:04d}")

    rec = sub.add_parser("reconcile", help="prove no inbox row was lost")
    _transport_args(rec)
    rec.add_argument("--committed", required=True,
                     help="NDJSON ledger written by `run --committed-out`")
    rec.add_argument("--limit", type=int, default=INBOX_LIMIT_CAP)
    return ap


def main() -> int:
    ap = build_parser()
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if not a.cmd:
        ap.print_help()
        return 2
    try:
        if a.cmd == "run":
            return cmd_run(a)
        if a.cmd in ("rate", "notify-rate"):
            return cmd_rate(a)
        if a.cmd == "hold":
            return cmd_hold(a)
        if a.cmd == "preflight":
            return cmd_preflight(a)
        if a.cmd == "reconcile":
            return cmd_reconcile(a)
    except HarnessError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
