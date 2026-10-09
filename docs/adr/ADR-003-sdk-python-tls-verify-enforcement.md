---
layout: doc
---
# ADR-003 - Python SDK TLS verification: post-handshake enforcement (vote record for 785838d82, #6308)

Status: **ACCEPTED + IMPLEMENTED** (commits 785838d82 and the round-4 fix on `fix/6060-promo6-ssh`).

Context: commit 785838d82 refused `CERT_OPTIONAL` contexts and added a per-request
refusal hook (a T3 security-posture choice) without the vote that
`4d3ea1c5` requires. This record documents the retroactive 5-agent vote
(4d3ea1c5) that ratifies both, and the vote that selected the exact-type
predicate plus a post-handshake check as the enforcement. Issues: #6267, #6268,
#6305, #6306, #6308.

Decision: the SDK accepts a caller `ssl.SSLContext` only when it is exactly
`ssl.SSLContext` with stock handshake attributes (early, clear error), and
enforces after every TLS handshake, before any request byte is sent, that the
negotiated session uses the caller's context object and carries a non-empty
peer certificate. Failure closes the stream and raises `ValueError` (fail closed).

## Vote record

# 6060 r4 vote: acceptance predicate for a caller-supplied ssl.SSLContext (#6267 #6268)

Protocol: 5-agent vote (4d3ea1c5). Triggers: T1 (public SSLContext acceptance contract narrows) + T3 (fail-closed posture).
Runner: ai:f1-fix-6060-r4. Date 2026-10-09. Base head 9c05728f0.

Options:
- A: isinstance(ctx, ssl.SSLContext) + base-descriptor CERT_REQUIRED/check_hostname + type(ctx).wrap_socket/wrap_bio are the base functions (subclasses with stock wrap methods allowed).
- B: exact type `type(ctx) is ssl.SSLContext` + base-descriptor CERT_REQUIRED/check_hostname + no instance-__dict__ shadowing of any ssl.SSLContext attribute (wrap_socket, wrap_bio, verify_mode, check_hostname, ...). Re-run on every request.
- C: current predicate + denylist (truststore) + wrap_* checks.

| Lens | Verdict | Confidence | Top risk | Killer objection |
|---|---|---|---|---|
| precedent | B | 70 | truststore / subclass users hit a hard ValueError; document create_default_context / CA path | refuses the common harmless subclass; C-level state mutation after check |
| spec-literalism | A | 66 | subclass overriding other handshake hooks (__getattribute__, sslsocket_class) | A cannot be proven complete; only B closes it |
| client-compat | A | 66 | identity checks miss override points (__getattribute__, __class__, _ctx delegation) | same: B's closed set is easier to prove |
| testability | B | 85 | class-level monkeypatch of ssl.SSLContext or post-check mutation; needs per-request re-check | rejects legitimate subclasses, forces create_default_context + load_verify_locations |
| blast-radius | B | 80 | corporate truststore users; no opt-in escape hatch | over-tight, no opt-in |

Tally: B 3, A 2, C 0. Verdict: B (exact type).

Note against the conductor's brief: the brief spelled form A (subclass with unmodified wrap methods). The vote prefers B, so B is implemented. Both A and B refuse truststore.SSLContext; B additionally refuses subclasses with stock wrap methods because A leaves __getattribute__/sslsocket_class/metaclass holes (testability, spec-literalism, client-compat all named them). Reversibility favours B (relaxing later breaks nobody; tightening later does).

Executed form: type(ctx) is ssl.SSLContext; base descriptors CERT_REQUIRED + check_hostname; no key of vars(ctx) names an attribute of ssl.SSLContext; ssl.SSLContext.wrap_socket/wrap_bio still the functions captured at import (class-level patch). Refusal message names the accepted forms and the workaround (ssl.create_default_context(cafile=...), verify=<CA path>).

---

# Round 2 of the vote: primary control, and ratification of 785838d82 (#6305 #6306 #6308)

Protocol: 5-agent vote (4d3ea1c5). Triggers: T3 (security/governance posture: new post-handshake gate, plus retroactive ratification of 785838d82's CERT_OPTIONAL refusal and per-request refusal hook, which shipped without a vote, #6308), T6 (>=2 enforcement paths).
Trigger: round-3 security verdict (REJECT) found that the exact-type predicate alone does not close #6305 (auth-null ciphers on a stock context), #6306 (check/use race) and the __getattribute__/sslsocket_class variants of #6268.

Questions:
- Q1: primary control. P = pre-handshake exact-type predicate only; T = post-handshake check only (negotiated ssl_object.context is the caller's context AND getpeercert() non-empty, installed per request through httpcore's trace extension at connection.start_tls.complete); B = both, predicate as the early clear-error path, trace as the enforcement.
- Q2: ratify 785838d82's refusal of CERT_OPTIONAL contexts.
- Q3: ratify 785838d82's per-request refusal hook.

| Lens | Q1 | Q2 | Q3 | Conf | Top risk |
|---|---|---|---|---|---|
| precedent | B | YES | YES | 78 | trace is httpcore-specific; a skipped event must fail closed |
| sync/async + concurrency | B | YES | YES | 72 | pooled/reused connections and HTTP/2 skip start_tls; sync vs async trace callables differ |
| spec-literalism | B | YES | YES | 80 | trace not invoked = fail open; abort must close the connection |
| testability | B | YES | YES | 78 | callback shape differs per httpcore version; needs canary + zero-bytes-sent assertions |
| blast-radius | B | YES | YES | 72 | context-identity check can false-positive on wrapper contexts (dissent: lenient predicate) |

Tally: Q1 B 5/0/0 (P 0, T 0); Q2 YES 5/0; Q3 YES 5/0. The blast-radius lens dissents only on keeping the exact-type predicate strict; round 1 of this vote (B 3-2) already decided that, and it stays.
Verdict: B (both). The trace/response check is the enforcement; the predicate stays as the early path and the clear error. 785838d82's CERT_OPTIONAL refusal and per-request hook are ratified.

Binding conditions taken from the voters' killer objections (all implemented and tested):
1. Fail closed: a request that carries no completed verified handshake is refused. A response-time backstop reads network_stream's ssl_object (covers pooled connections and a trace event that never fired).
2. Sync and async clients get matching sync/async trace callables; a caller-supplied trace extension is wrapped, never replaced.
3. The abort closes the stream before raising, and no request byte is sent (asserted with a recording server).
4. Canary test: the trace fires on both httpx pins; a mutation that removes the enforcement turns the tests red.
