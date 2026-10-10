---
layout: doc
---
# ADR-003 - Python SDK TLS verification: post-handshake enforcement (vote record for 785838d82, #6308)

Status: **ACCEPTED + IMPLEMENTED** (commits 785838d82, the round-4 fix and the round-5 series on `fix/6060-promo6-ssh`; round 5 below).

Context: commit 785838d82 refused `CERT_OPTIONAL` contexts and added a per-request
refusal hook (a T3 security-posture choice) without the vote that
`4d3ea1c5` requires. This record documents the retroactive 5-agent vote
(4d3ea1c5) that ratifies both, and the vote that selected the exact-type
predicate plus a post-handshake check as the enforcement. Issues: #6267, #6268,
#6305, #6306, #6308.

Decision: the SDK accepts a caller `ssl.SSLContext` only when it is exactly
`ssl.SSLContext` with stock handshake attributes, verification and hostname
checks on, no verify flag that relaxes chain validation and no cipher suite
without server authentication. This check runs at construction and again before
every request, which gives an early, clear error. After every TLS handshake of a
request (direct, through an `http://` or `https://` CONNECT proxy, or over
SOCKS), and before that request's first byte is written on the connection, the
SDK enforces that the negotiated session:
- uses the caller's context object
- carries a non-empty peer certificate that names the request host and whose
  validity dates include now
- negotiated a cipher with secret bits

Failure closes the stream and raises `ValueError` (fail closed). A response-time
backstop repeats the check on the connection the response came over. It covers a
pooled connection and a trace event that never fired, but it runs after the
request was written. The pre-send check is installed inside every transport of
the client (the default one and each mounted proxy transport), so it runs after
all request event hooks: a caller hook cannot replace or remove it, and a trace
a hook sets is chained after the SDK's (#6537). A client whose transports cannot
be wrapped is refused at construction.

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

---

# Round 5: every session of a request, and what "verified" means (#6349 #6350 #6375 #6305 #6376 #6377)

Protocol: 3-agent vote (6def5ab6), operator directive relayed by ai:god-f2. Runner: ai:f1-fix-6060-r5, 2026-10-09.
Memory: bdb2d654 (vote record); round-4 votes 5d31459d stand.

Q1 (#6349 #6376): which TLS sessions the post-handshake check acts on, and how an `https://` proxy leg is treated.
Options: A, check every `*.start_tls.complete` session against the caller's context, and admit a session on another
context only on `connection.start_tls` as a per-request "pending" proxy leg that a verified origin session must follow
before any request other than the bare tunnel CONNECT is written; B, force `trust_env=False`; C, skip sessions whose
server name differs from the request host. Lenses fail-closed security, client-compat, testability/spec: A 3, B 0, C 0.
Verdict: A. Binding conditions: pending state per request; the CONNECT exemption admits only httpcore's own CONNECT
(Host, Accept, Proxy-Authorization headers); the trace closes the stream itself before raising; tests drive the
branches a real server cannot reach.

Decisions below the vote threshold (recorded as `decision:` lines in the commits):
- #6350: the peer certificate must name the request host (the URL host, not the proxy). A DNS SAN wildcard matches
  only as the whole left-most label of a name with at least three labels (`*.example.com`, never `f*.example.com`
  or `*.com`), and never more than one label; an IP host matches only an IP SAN; the subject
  CN is used only when the certificate has no DNS SAN and the context's `hostname_checks_common_name` is on.
- #6375: verify flags are an allowlist. `VERIFY_X509_PARTIAL_CHAIN` is admitted, because Python 3.13+
  `create_default_context` sets it; a flag that relaxes validation, such as `VERIFY_X509_NO_CHECK_TIME` or
  `VERIFY_ALLOW_PROXY_CERTS`, is refused.
- #6305: a context offering a suite without server authentication (auth-null, PSK, SRP, eNULL) is refused at
  construction. Cost: the plain OpenSSL `"DEFAULT"` cipher string and some system cipher policies include PSK and SRP
  suites and are refused; the error message gives the remedy string.
- #6377: `verify=<CA path>` is read once, at construction. For a directory, only the hashed entries OpenSSL's own
  `capath` lookup reads (`<hash>.<n>`, `<hash>.r<n>`) are loaded. A group- or world-writable directory, file, symlink
  target or target directory is refused (POSIX). An empty directory gives a context with no trust anchor, which fails
  every handshake (#6269).
- #6559 / #6653 / #6654 (3-agent vote (6def5ab6); Q1 3-0, Q2 2-1, Q3 2-1): every directory the path passes through,
  an ancestor of the CA path, of a symlink met on the way, or of a link's target, is held to the rule for a CA file's
  directory. It must be owned by this user or root (OpenSSH StrictModes), and must not be group- or world-writable
  unless it is sticky and the entry in it belongs to this user or root (a `/tmp`-style ancestor with a private
  subdirectory is accepted). Whoever can change such a directory can swap a subdirectory, re-point a link or replace
  the file, and an ABA swap of an ancestor during the load is invisible to the inode re-check, so the refusal comes
  before anything is read. The file is still loaded by path and re-checked to be the same inode afterwards (Q3).
  Intended break: a CA path under a group-writable directory is refused, e.g. Homebrew's `/opt/homebrew/etc`
  (`drwxrwxr-x` with group `admin`) and Intel-mac `/usr/local` trees; the error names the directory, its owner uid
  and mode, and the fix (`chmod go-w <dir>`, or `chown` for a directory owned by another user), or copy the bundle to
  a private directory. No parameter turns the check off.

Residuals (accepted, each with its reason):
- The validity-date check after the handshake reads the leaf only, because `getpeercert()` returns no chain.
  OpenSSL checks every certificate's dates during the handshake, and the flag that would turn that off
  (`VERIFY_X509_NO_CHECK_TIME`) is refused.
- The `https://` proxy leg is authenticated by httpx's own default context (`SSL_CERT_FILE` / `SSL_CERT_DIR` /
  certifi), not by the caller's context. No SDK secret crosses that leg: only httpcore's CONNECT, with the caller's
  own `Proxy-Authorization` when the proxy URL carries credentials. The origin session inside the tunnel is held to
  the caller's context.
- The response backstop cannot stop a request that was already written; it exists for the paths where the pre-send
  trace did not run. The trace lives in the transport, after every request event hook (#6537).
- `verify=None` / `verify=True` with `SSL_CERT_FILE` or `SSL_CERT_DIR` set: the SDK loads that path itself under the
  rules above (read once, permissions checked), and refuses a missing or wrong-kind path instead of httpx 0.27's
  silent fallback to certifi (#6538).
