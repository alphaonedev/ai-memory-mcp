#!/usr/bin/env python3
# check-foreign-text-to-caller.py — #3688 gate 7: FOREIGN TEXT CROSSING TO A CALLER.
#
# The rule keys on two properties of a VALUE, neither of which is a name:
#   SOURCE  the value is FOREIGN — it originated outside our own code: a backend driver's
#           error (sqlx, rusqlite, the anyhow chains that wrap them), a peer's or provider's
#           HTTP body, a subprocess's stdout, an operator path / DSN label.
#   SINK    it reaches a CALLER-FACING surface — an HTTP JSON error body, an MCP tool error,
#           a governance Deny.reason, or a stored record a caller later reads back
#           (subscription_dlq.last_error, federation_push_dlq).
# Foreign-in, caller-out is the whole rule. An operator LOG is a different audience (TIER 2)
# and is never a finding here; a validator echoing the caller's own input back is not a defect.
#
# The passing state is RENDERED FROM AN ALLOWLIST (a typed mapper: store_err_to_response,
# handler_error_500, sanitize_store_err_message, ProviderError, QuorumNotMetPayload,
# http_status_reason) or DROPPED — never MASKED. Anything named redact_* / mask_* / scrub_* is
# TRANSPARENT: the taint passes straight through it, and an allowlist entry that names one is
# itself a FAIL. (redact_url_password masks only a userinfo password; the gate-2 lesson.)
#
# Provenance, not names: for every rendered identifier the gate walks to its binding site —
# `Err(e) =>` (the match subject), `.map_err(|e| ..)` (the receiver chain), `let x = ..`,
# `for x in ..`, a fn parameter (its call sites), a struct field (its constructions) — and
# classifies the PRODUCER. The funnel `store_err_to_response` is itself a sink: every arm that
# renders `e.to_string()` unsanitised is walked back through the variant's text fields to their
# construction sites, which is how a DSN label that reaches a 503 body is found without any
# name matching.
#
# The SINK SET is DERIVED from the tree on every run, never enumerated (#3760): the HTTP sinks are
# every handler `src/lib.rs` routes (+ `middleware::from_fn[_with_state]`) closed over the callees
# whose return type is response-shaped; the MCP sinks are every `register_mcp_tool!` dispatch entry
# (+ `handle_request`) closed over the callees whose error type is the wire type (`Result<_, String>`)
# reached by VERBATIM propagation (`..)?`, a tail, a `return`, an arm value). Inside them EVERY
# `json!()` value at ANY key and nesting is a sink, as are `(StatusCode, ..)` tuples, `err_response`,
# `Err(..)` / `map_err` payloads and `Ok(json!(..))` results; a pushed collection is produced by its
# pushes; a `match` value by its arms. Before #3760 the sinks were the literal key `"error"` under
# three path prefixes and `Err(` under `src/mcp/`, which is how the import envelope's `"errors"`
# array carrying a StoreError Display (admin.rs:1577) was never examined. A response-shaped fn no
# route reaches is dead code, not a sink (the self-test's `unrouted_leak` control); the summary
# prints the derived counts so a run that derived nothing cannot read as a pass. The pre-#3760
# analyzer is frozen VERBATIM at scripts/test/fixtures/foreign-text-prefix-3760.py (R-203).
#
# Block bodies are judged by their EXITS (#3711 gate-7 finding): a `.map_err(|e| { ..; format!(..) })`
# or arm body renders only its tail expression and its `return <x>` payloads, each resolved at its own
# offset so a `let` inside the block is a binding site. Judging the whole block as one expression let
# any OWN marker in a preceding statement (`e.classify()`, a validate_*, a parse) launder a `{text}`
# the tail interpolated; the frozen pre-fix copy at scripts/test/fixtures/foreign-text-prefix-3711.py
# is the R-203 control that still accepts that shape.
#
# The RECEIVER of a `.map_err(|e| ..)` chain is bounded by STATEMENTS (#3767): scanning backwards
# from the chain, a `}` at depth 0 belongs to the receiver only when everything between it and the
# chain is chain continuation (`.name(..)`, `?`, `.await`) — `match .. { .. }.map_err(..)`,
# `Foo { .. }.x()`. Any other expression text in between means that `}` closes a PRECEDING block
# statement (`if .. { return Err(..); }`) and the receiver starts after it. Before #3767 the scan
# read every `}` as a nested closer and swallowed the preceding block into the receiver, so an
# OWN marker inside it (`..kind_authorized(`) laundered the call that followed: the crate fns
# `crate::checkpoints::insert` (declared `rusqlite::Result`) and `db::insert` (an anyhow chain over
# `conn.execute(..)?`) were ALREADY classified as db sources from their signatures — the walk never
# reached them (`memory_checkpoint_create` shipped `no such table: checkpoints`, #3766). The
# pre-#3767 analyzer is frozen VERBATIM at scripts/test/fixtures/foreign-text-prefix-3767.py (R-203).
# Callee resolution is deterministic: the source tree is walked in sorted order and a module-tail
# qualifier (`db::` = `src/storage/`) resolves to the module ROOT (`mod.rs`) before any sibling file.
#
# Usage:
#   scripts/check-foreign-text-to-caller.py [ROOT] [--json] [--verbose] [--only=<src/file.rs>]
#   scripts/check-foreign-text-to-caller.py --self-test
# Allowlist: scripts/qc-allowlists/foreign-text-to-caller.txt (absent = empty). Grammar:
#   <key>=echo:<why>      the rendered value is the CALLER'S OWN input (echo direction)
#   <key>=pending:#NNNN   a real finding held under a tracked issue (INFO while open; a stale entry is a NOTICE)
#   mapper=<fn_name>      declare an additional TYPED mapper whose output is caller-safe
# A key is <file>:<fn>:<sink-kind>:<source-kind>. There is deliberately no grammar that
# acknowledges a foreign value as "masked".
# Cargo-free, stdlib only.
import os, re, sys, json, collections

MAX_DEPTH = 14

def analyze(ROOT, ALLOWF='', VERBOSE=False, ONLY=None):
    """Run the gate over ROOT/src. Returns (findings, counts)."""

    # ---------------------------------------------------------------- source load
    def strip_comments(text):
        """Remove // comments (string-aware, line-preserving); keep line count."""
        out = []
        for line in text.split('\n'):
            res = []; i = 0; in_s = False; esc = False
            while i < len(line):
                c = line[i]
                if in_s:
                    res.append(c)
                    if esc: esc = False
                    elif c == '\\': esc = True
                    elif c == '"': in_s = False
                else:
                    if c == '"': in_s = True; res.append(c)
                    elif c == '/' and i + 1 < len(line) and line[i+1] == '/': break
                    elif c == "'" and i + 2 < len(line) and line[i+2] == "'": res.append(line[i:i+3]); i += 2
                    else: res.append(c)
                i += 1
            out.append(''.join(res))
        return '\n'.join(out)

    def find_matching(text, i, open_c, close_c):
        depth = 0; in_s = False; esc = False; n = len(text)
        while i < n:
            c = text[i]
            if in_s:
                if esc: esc = False
                elif c == '\\': esc = True
                elif c == '"': in_s = False
            elif c == '"': in_s = True
            elif c == "'" and i + 2 < n and text[i+2] == "'": i += 2
            elif c == open_c: depth += 1
            elif c == close_c:
                depth -= 1
                if depth == 0: return i
            i += 1
        return -1


    files = {}   # path -> {'lines': [...], 'prod_end': n}
    for dp, dn, fn in os.walk(os.path.join(ROOT, 'src')):
        dn.sort()   # #3767 — a deterministic index order: `find_fn`'s first candidate must not depend on the filesystem
        for f in sorted(fn):
            if not f.endswith('.rs'): continue
            p = os.path.relpath(os.path.join(dp, f), ROOT)
            base = os.path.basename(p)
            if base == 'tests.rs' or 'test' in base and base != 'attest.rs' and re.search(r'(_|^)tests?(_|\.)', base): continue
            raw = open(os.path.join(ROOT, p), encoding='utf-8', errors='replace').read()
            txt = strip_comments(raw)
            # #3760 — a CHAR literal (`'"'`, `'\\''`) is blanked at load (length-preserving): a lone `"`
            # inside one opened a string for the literal-blanking regexes and swallowed the binding
            # sites that followed (`trim_matches('"')` hid an `Err(e) =>` arm 200 lines below it).
            txt = re.sub(r"'(?:\\\\.|[^'\\\\\\n])'", lambda m: "'" + ' ' * (len(m.group(0)) - 2) + "'", txt)
            # Blank out every test module IN PLACE (line numbers preserved): `mod tests {..}` and any
            # `#[cfg(test)] mod x {..}` — they can sit in the middle of a file with production code after.
            for m in reversed(list(re.finditer(r'(?m)^\s*(?:#\[cfg\(test\)\]\s*\n\s*)?(?:pub(?:\([a-z]+\))?\s+)?mod\s+\w+\s*\{', txt))):   # reverse: offsets stay valid
                head = m.group(0)
                if '#[cfg(test)]' not in head and not re.search(r'mod\s+tests\s*\{', head): continue
                e = find_matching(txt, m.end()-1, '{', '}')
                if e < 0: continue
                seg = txt[m.start():e+1]
                txt = txt[:m.start()] + re.sub(r'[^\n]', '', seg) + txt[e+1:]
            lines = txt.split('\n')
            files[p] = {'lines': lines, 'text': txt}

    # ------------------------------------------------------------- function index
    FN_RE = re.compile(r'\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(<[^{;]*?>)?\s*\(')
    class Fn:
        __slots__ = ('file', 'name', 'start', 'body_start', 'end', 'params', 'sig', 'impl_type')
    fns_by_file = collections.defaultdict(list)
    fns_by_name = collections.defaultdict(list)

    def line_of(text, idx): return text.count('\n', 0, idx) + 1

    IMPL_RE = re.compile(r'\bimpl(?:<[^>]*>)?\s+(?:[A-Za-z0-9_:<>,\s]+?\s+for\s+)?([A-Za-z_][A-Za-z0-9_]*)')
    for p, d in files.items():
        text = d['text']
        # impl blocks: (start, end, type)
        impls = []
        for m in IMPL_RE.finditer(text):
            b = text.find('{', m.end())
            if b < 0: continue
            e = find_matching(text, b, '{', '}')
            if e < 0: continue
            impls.append((b, e, m.group(1)))
        for m in FN_RE.finditer(text):
            pstart = m.end() - 1
            pend = find_matching(text, pstart, '(', ')')
            if pend < 0: continue
            # body: next '{' after ')' that is not part of a where-clause type... find ';' or '{'
            j = pend + 1; body = -1
            while j < len(text):
                c = text[j]
                if c == ';': break
                if c == '{': body = j; break
                j += 1
            if body < 0: continue
            end = find_matching(text, body, '{', '}')
            if end < 0: continue
            f = Fn(); f.file = p; f.name = m.group(1); f.start = line_of(text, m.start())
            f.body_start = body; f.end = end; f.sig = text[m.start():body]
            params = []
            for part in re.split(r',(?![^<(]*[>)])', text[pstart+1:pend]):
                mm = re.match(r'\s*(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+)', part.strip(), re.S)
                if mm: params.append((mm.group(1), mm.group(2).strip()))
            f.params = params
            f.impl_type = None
            for (b, e, t) in impls:
                if b < m.start() < e: f.impl_type = t
            fns_by_file[p].append(f)
            fns_by_name[f.name].append(f)

    # one-pass indexes: every `ident(` call site and every `Ident {` construction, crate-wide
    CALL_SITES = collections.defaultdict(list)     # name -> [(file, pos, qualifier, is_method)]
    CONSTRUCTIONS = collections.defaultdict(list)  # TypeName -> [(file, pos)]
    SELF_CONSTRUCTIONS = []                        # [(file, pos)]
    _call_rx = re.compile(r'(?<![A-Za-z0-9_])(\.?)((?:[A-Za-z_][A-Za-z0-9_]*::)*)([a-z_][a-z0-9_]*)\s*\(')
    _ctor_rx = re.compile(r'(?<![A-Za-z0-9_])((?:[A-Za-z_][A-Za-z0-9_]*::)*)([A-Z][A-Za-z0-9]*)\s*\{')
    for p, d in files.items():
        text = d['text']
        for m in _call_rx.finditer(text):
            if text[max(0, m.start()-3):m.start()].endswith('fn'): continue
            CALL_SITES[m.group(3)].append((p, m.start(), m.group(2), m.group(1) == '.'))
        for m in _ctor_rx.finditer(text):
            if m.group(2) == 'Self': SELF_CONSTRUCTIONS.append((p, m.start()))
            else: CONSTRUCTIONS[m.group(2)].append((p, m.start()))

    def enclosing_fn(p, idx):
        best = None
        for f in fns_by_file[p]:
            if f.body_start <= idx <= f.end:
                if best is None or f.body_start > best.body_start: best = f
        return best

    # ------------------------------------------------- derived sink functions (#3760)
    # The set of CALLER-FACING functions is DERIVED from the tree on every run, never hand-listed
    # and never a path prefix:
    #   HTTP — every handler the router REGISTERS (`src/lib.rs` `.route(_, get|post|..(<h>))` and
    #          `middleware::from_fn[_with_state](<f>)`), closed transitively over the fn index to
    #          every callee whose return type is response-shaped (Response / IntoResponse /
    #          `(StatusCode, ..)` / Json<..>). A response-shaped fn nothing routed reaches is dead
    #          code, not a sink; a helper any handler reaches IS one, wherever it lives.
    #   MCP  — every `register_mcp_tool!(_, dispatch_x)` wrapper (the `tools/call` table) plus
    #          `handle_request`, closed over every callee whose error type is the WIRE type
    #          (`Result<_, String>`): an `Err(String)` produced there propagates through `?` to the
    #          tool result, so it is a sink wherever the file sits (`src/mcp/**` was the old proxy).
    # Before #3760 the sinks were an ENUMERATION: the literal JSON key `"error"` under three path
    # prefixes, and `Err(` under `src/mcp/`. The import envelope's `"errors": [..]` array, fed by
    # `errors.push(format!("..{e}"))` from a StoreError, was invisible to both.
    def last_seg(path): return path.strip().split('::')[-1]
    HTTP_ROOTS = set(); MCP_ROOTS = set()
    lib = files.get('src/lib.rs')
    if lib:
        t = lib['text']
        for m in re.finditer(r'\.route\s*\(', t):
            e = find_matching(t, m.end()-1, '(', ')')
            if e < 0: continue
            for hm in re.finditer(r'\b(?:get|post|put|delete|patch|head|options|any|trace)\s*\(\s*([A-Za-z_][A-Za-z0-9_:]*)\s*\)', t[m.end():e]):
                HTTP_ROOTS.add(last_seg(hm.group(1)))
        for hm in re.finditer(r'\bfrom_fn(?:_with_state)?\s*\(\s*(?:[^,()]+,\s*)?([A-Za-z_][A-Za-z0-9_:]*)\s*\)', t):
            HTTP_ROOTS.add(last_seg(hm.group(1)))
    mcp = files.get('src/mcp/mod.rs')
    if mcp:
        for hm in re.finditer(r'register_mcp_tool!\s*\(\s*[^,]+,\s*([A-Za-z_][A-Za-z0-9_:]*)\s*\)', mcp['text']):
            MCP_ROOTS.add(last_seg(hm.group(1)))
        if fns_by_name.get('handle_request'): MCP_ROOTS.add('handle_request')
    RESP_SIG_RE = re.compile(r'->\s*(?:[^{;]*?)(?:\bResponse\b|IntoResponse|\(\s*(?:axum::http::|http::)?StatusCode\b|\bJson\s*<)')
    WIRE_ERR_SIG_RE = re.compile(r'->\s*(?:[^{;]*?)Result\s*<.*,\s*String\s*>', re.S)
    def reach(roots, keep, edge=None):
        """Transitive closure over the fn index from `roots`: a callee joins the set when `keep(fn)`
        holds for its definition AND (when `edge` is given) the CALL SITE satisfies `edge(body, m, e)`
        — used on the MCP side to follow only VERBATIM error propagation (`..)?`), because a
        transformed error (`.map_err(..)`) is judged at the transformation site, which is already a
        sink, and the taint walk enters the callee from there. Name-level, so a same-named fn in
        another impl over-approximates rather than under-approximates."""
        # Members are DEFINITIONS, keyed (file, name): a storage fn that happens to share a
        # handler's name (`register_agent`) is not a handler. A root joins only if its definition
        # has the shape (`keep`); a callee joins per definition that has it.
        seen = {(g.file, g.name) for n in roots for g in fns_by_name.get(n, []) if keep(g)}
        frontier = list(seen)
        for _ in range(12):
            if not frontier: break
            nxt = []
            for (fp, name) in frontier:
                for g in fns_by_name.get(name, []):
                    if g.file != fp: continue
                    body = files[g.file]['text'][g.body_start:g.end]
                    for cm in _call_rx.finditer(body):
                        c = cm.group(3)
                        if c not in fns_by_name: continue
                        if edge is not None:
                            e = find_matching(body, cm.end() - 1, '(', ')')
                            if e < 0 or not edge(body, cm, e): continue
                        qual = cm.group(2).rstrip(':').split('::')[-1] if cm.group(2) else ''
                        is_method = cm.group(1) == '.'
                        cands_ = [h for h in fns_by_name[c] if keep(h)]
                        if qual and qual != 'Self' and qual[:1].isupper():
                            cands_ = [h for h in cands_ if h.impl_type == qual]          # `Type::new(..)` names its impl
                        elif is_method:
                            impls_ = {h.impl_type for h in cands_ if h.impl_type}
                            if len(impls_) > 1: continue                                  # `x.new(..)`: receiver type unknown, name ambiguous
                        for h in cands_:
                            k = (h.file, h.name)
                            if k in seen: continue
                            seen.add(k); nxt.append(k)
            frontier = nxt
        return seen
    def propagates_verbatim(body, cm, e):
        """The callee's Result leaves the caller UNCHANGED: `callee(..)?` / `.await?`, a tail
        expression (`{ callee(..) }`), a `return callee(..)`, or a match-arm value
        (`Kind::X => callee(..),`). A `;`-terminated call drops it; a `.map_err(..)` transforms it
        (and is a sink of its own)."""
        after = body[e+1:e+16]
        if re.match(r'\s*(?:\.await)?\s*\?', after): return True
        tail = re.match(r'\s*(?:\.await)?\s*(\}|,|\Z)', after)   # \Z: the body slice excludes its closing brace
        if not tail: return False
        before = body[max(0, cm.start()-40):cm.start()].rstrip()
        return tail.group(1) != ',' or before.endswith('=>') or before.endswith('return')
    HTTP_FNS = reach(HTTP_ROOTS, lambda g: bool(RESP_SIG_RE.search(g.sig.replace('\n', ' '))))
    MCP_KEEP = lambda g: bool(WIRE_ERR_SIG_RE.search(g.sig.replace('\n', ' '))) or g.name in MCP_ROOTS
    MCP_FNS = reach(MCP_ROOTS, MCP_KEEP, propagates_verbatim)
    DERIVED = {'http_roots': len(HTTP_ROOTS), 'http_fns': len(HTTP_FNS), 'mcp_roots': len(MCP_ROOTS), 'mcp_fns': len(MCP_FNS)}

    # ------------------------------------------------------------- classification
    # Typed mappers whose OUTPUT is caller-safe by construction. Anything else that
    # merely masks (redact_*, mask_*, scrub_*) is TRANSPARENT: taint passes through.
    CLEAN_MAPPERS = [
        r'store_err_to_response\(', r'handler_error_500\(', r'sanitize_store_err_message\(',
        r'sanitize_bulk_row_error\(', r'http_status_reason\(', r'QuorumNotMetPayload', r'under_replicated_response\(',
        r'\.transport_error\(', r'\.http_error\(', r'ProviderError', r'ProviderFailure', r'DlqErrorClass', r'BulkRowErrorClass',
        r'create_pg_store_err_to_response\(', r'classify_store_err\(', r'attestation_refused_response\(', r'reject_class\(',
    ]
    CLEAN_RE = re.compile('|'.join(CLEAN_MAPPERS))
    # A helper that renders its text param ONLY behind a typed-code guard (`if msg.contains(error_codes::X)`).
    GUARD_RE = re.compile(r'\.(contains|starts_with)\(\s*(?:crate::)?(?:errors::)?error_codes::[A-Z_]+\s*\)')
    # Whole-expression scalars: a status code, a length, a constant — never text that could carry foreign bytes.
    SCALAR_RE = re.compile(r'^[\s&*(]*(?:[A-Za-z_][\w.:]*)?(?:\.(?:len|count|as_u16|as_u64|as_i64|status|status_code|code|content_length|elapsed|attempts|is_[a-z_]+|as_str_code)\(\)|StatusCode::[A-Z_]+|error_codes::[A-Z_]+|msg::[A-Z_]+|[A-Z][A-Z0-9_]{2,})[\s)]*(?:\.(?:to_string|as_u16|to_owned|clone)\(\))?[\s)]*$')
    # Values produced by our OWN code from the caller's own input (echo direction).
    # `std::fs::canonicalize` / `.canonicalize()` RESOLVE a filesystem path (the #3713 std::fs shape) — the
    # FOREIGN `path` head above claims them before OWN_RE's `\bcanonical` (our normalisers) can (#3760).
    OWN_RE = re.compile(r'\bvalidat|[Rr]ejection|Validator|Validation|\bparse_[a-z_]*\(|::parse\(|\.parse::<|\bauthoriz|serde_json::from_|from_str\(|is_visible|resolve_read|CallerContext|\bcaller\b|\bcanonical|\bnormali[sz]e|\bclassify|to_rfc3339|Utc::now|from_rfc3339|\bDecode\b|\bdecode_[a-z_]*\(|base64|\bhex::|\bparse\b')
    FOREIGN = [
        ('db',   re.compile(r'\bapp\.store\b|\.store\.[a-z_]+\(|\bstore\.[a-z_]+\(|\bdb::[a-z_:]*[a-z_]\(|\bstorage::[a-z_:]*[a-z_]\(|\block\.0\b|\bconn\b|\btx\b|\bsqlx\b|\brusqlite\b|\.execute\(|\.query[a-z_]*\(|\.prepare\(|\bpool\b|Connection::open')),
        ('http', re.compile(r'\breqwest\b|\.send\(\)|\.send_async|\.text\(\)|\b(?:resp|response)\.(?:bytes|json|take|read_to_string|chunk|body|text|error_for_status)\(|\.bytes\(\)\.await|\.json::<|\bclient\.(?:get|post|put|delete|request|head)\(|\bureq\b|\back_body\b|\bhyper::')),
        ('proc', re.compile(r'\bCommand::|\.output\(\)|wait_with_output|\bstdout\b|\bstderr\b|\.fire\(|run_hook|drive_exec|\bexchange\(|\bchild\b|ExecutorError|HookDecision::parse')),
        ('path', re.compile(r'(?:std::)?fs::canonicalize\b|\.canonicalize\b|effective_db|\bdb_path\b|\bkey_dir\b|keys_dir|config_path|config_dir|\blog_dir\b|audit_dir|env::var(?:_os)?\(\s*(?:[A-Z_]*_(?:DIR|ROOT|PATH|FILE)(?:_ENV)?|"AI_MEMORY_[A-Z_]*_(?:DIR|ROOT|PATH|FILE)")|home_dir\(|data_local_dir|config_local_dir|witness_key_dir|recorder_key_dir|\.db_path|\bdb\.path|lock\.1\b|passphrase_file|erasure_dir')),
        ('dsn',  re.compile(r'redact_url|redact_urls_in_message|\bstore_label\b|\bstore_url\b|\bdsn\b|resolve_store_url|federation_forward_url|\bbase_url\b|quorum_peers|\bpeer_url\b|\bpeers\b')),
    ]
    TEXTISH_TYPES = re.compile(r'\bstr\b|String|Cow<|Display|\bValue\b|Result<|Option<|Vec<|PathBuf|\bPath\b|Error|\[u8\]|Bytes|Outcome|Report|Decision')
    HANDLE_TYPES = re.compile(r'Connection|\bDb\b|AppState|Mutex|Pool|Client|Arc<|Transaction|&mut |Embedder|Reranker|Index|Keypair|SigningKey|Config\b|Option<&?(Connection|AppState)')
    FOREIGN_TYPES = re.compile(r'\b(StoreError|rusqlite::Error|sqlx::Error|reqwest::Error|anyhow::Error|ExecutorError|BoxBackendError|DecisionParseError)\b')

    LIT_RE = re.compile(r'"(?:[^"\\]|\\.)*"', re.S)
    class T:  # taint verdict
        __slots__ = ('kind', 'why')
        def __init__(self, kind, why): self.kind = kind; self.why = why
        def __bool__(self): return self.kind is not None
    CLEAN = T(None, 'clean')

    def norm(e):
        """Join rustfmt-split method chains: `app\\n  .store\\n  .x(` -> `app.store.x(`."""
        return re.sub(r'\s*\.\s*(?=[A-Za-z_])', '.', e)
    PARSE_RE = re.compile(r'serde_json::from_|from_str\(|from_utf8|from_slice|\.parse::<|\.parse\(\)|\bparse_[a-z_]*\(|::parse\(|\bdecode|base64|\bhex::|\.get\("|\.as_str\(\)|\.trim\(\)|\.lines\(\)|\.split|\.chars\(\)|String::from_utf8|\.to_owned\(\)|\.into\(\)')
    TYPED_FROM_RE = re.compile(r'(?<!String::)(?<!Vec::)(?<!PathBuf::)(?<!HashMap::)(?<!BTreeMap::)[A-Z][A-Za-z0-9]*::(from_(?!str\b|utf8|slice|reader|value)[a-z_]+|parse|resolve|build|of)\(')
    NUMERIC_RE = re.compile(r'parse::<(u\d+|i\d+|usize|isize|f\d+)>\(\)\s*$|^\s*\d+\s*$')
    PATH_CTOR_RE = re.compile(r'(?:(?:std::)?fs::[a-z_]+|\bPath(?:Buf)?::(?:new|from)|\.(?:join|canonicalize|with_extension|with_file_name|parent|display|to_path_buf))\s*$')
    def blank_call_args(e):
        """Length-preserving blank of every parenthesised ARGUMENT list at any depth — EXCEPT the
        arguments of a PATH constructor / resolver (`std::fs::canonicalize(&key_dir)`, `Path::new(..)`,
        `.join(..)`): a resolved path IS its argument (the #3713 std::fs shape)."""
        out = list(e); depth = 0; in_s = False; esc = False
        keep_depth = None   # depth at which a path-constructor argument list opened
        for i, c in enumerate(e):
            if keep_depth is not None:
                if c == '(' and not in_s: depth += 1
                elif c == ')' and not in_s:
                    depth -= 1
                    if depth < keep_depth: keep_depth = None
                if c == '"' and not esc: in_s = not in_s
                continue
            if in_s:
                if esc: esc = False
                elif c == '\\': esc = True
                elif c == '"': in_s = False
                if depth > 0: out[i] = ' '
                continue
            if c == '"': in_s = True
            if c == '(':
                if depth == 0 and PATH_CTOR_RE.search(e[max(0, i-40):i]):
                    keep_depth = 1; depth += 1; continue
                depth += 1
                if depth > 1: out[i] = ' '
                continue
            if c == ')':
                depth -= 1
                if depth > 0: out[i] = ' '
                continue
            if depth > 0: out[i] = ' '
        return ''.join(out)

    def classify_expr(expr, side='err'):
        """Textual classification of a producing expression (string literals are NOT evidence).
        side='err'   : the expression PRODUCED AN ERROR we are about to render (its Display is the payload).
        side='value' : the expression produced a VALUE (a parsed body, a read line, a label)."""
        inline_names = re.findall(r'\{([a-z_][a-z0-9_]*)(?:\.[a-z0-9_]+)*(?::[^}]*)?\}', expr)   # rendered INSIDE the format literal
        expr = norm(LIT_RE.sub('""', expr))
        if CLEAN_RE.search(expr) and not inline_names:
            # a typed mapper clears ONLY what it wraps: strip every mapper call and see what is still rendered
            rest = expr
            for _ in range(8):
                mm = CLEAN_RE.search(rest)
                if not mm: break
                op = rest.find('(', mm.start())
                if op < 0 or op > mm.end() + 2: rest = rest[:mm.start()] + rest[mm.end():]; continue
                cl = find_matching(rest, op, '(', ')')
                rest = rest[:mm.start()] + '""' + (rest[cl+1:] if cl > 0 else '')
            if not re.search(r'\{[a-z_][a-z0-9_]*[:}]|\b[a-z_][a-z0-9_]*\.to_string\(\)|(?:format|anyhow|bail)!\([^;]*,\s*&?[a-z_][a-z0-9_]*\s*[,)]', rest): return CLEAN
        if SCALAR_RE.match(expr.strip()) or NUMERIC_RE.search(expr): return CLEAN
        if side == 'value' and PARSE_RE.search(expr.split('(', 1)[0] + '('): return None   # a parsed VALUE inherits its input's taint
        head = expr.split('(', 1)[0]          # the producer is the call HEAD; its arguments are not evidence either way
        if head.strip():
            for kind, rx in FOREIGN:
                if side == 'value' and kind == 'db': continue
                m = rx.search(head)
                if m: return T(kind, m.group(0))
            if OWN_RE.search(head): return CLEAN
        if side == 'value':
            if PARSE_RE.search(expr): return None           # a parsed VALUE inherits the taint of its input
            if TYPED_FROM_RE.search(expr): return CLEAN     # a typed struct built by our own constructor
            if re.match(r'^\s*&?(?:[A-Za-z_][A-Za-z0-9_]*::)*[A-Z][A-Za-z0-9]*\s*\{', expr): return CLEAN   # a struct LITERAL of ours: its fields are judged when rendered (#3760)
            if OWN_RE.search(expr): return CLEAN
            # #3760 — a VALUE is produced by the receiver chain and the call heads, never by what is
            # passed INTO a call: `dispatch(ctx, db_path, ..)` does not make the result a path, and
            # `peer_status(&p.id, ..)` does not make it a peer URL. Arguments are blanked before the
            # marker search (the argument's own producer is judged when it is rendered).
            for kind, rx in FOREIGN:
                if kind == 'db': continue                    # rows we read are our own data
                m = rx.search(blank_call_args(expr))
                if m: return T(kind, m.group(0))
            return None
        if OWN_RE.search(expr): return CLEAN
        for kind, rx in FOREIGN:
            m = rx.search(expr)
            if m: return T(kind, m.group(0))
        return None   # unknown

    IDENT_RE = re.compile(r'(?<![A-Za-z0-9_:.])([a-z_][a-z0-9_]*)\b(?!\s*[(:!])')
    KEYWORDS = {'let','mut','if','else','match','return','as','in','for','while','loop','ref','move','async','await','true','false','self','crate','super','fn','impl','where','some','none','ok','err','pub','use','mod','struct','enum','type','dyn','box','static','const','continue','break','unsafe','trait'}

    def rendered_idents(expr):
        """Identifiers whose VALUE is rendered by expr: inline {x} (read from the ORIGINAL text — they live
        inside the format literal), positional args, x.to_string(), bare x (read literal-blind)."""
        ids = set()
        for m in re.finditer(r'\{([A-Za-z_][A-Za-z0-9_]*)(?:\.[A-Za-z0-9_]+)*(?::[^}]*)?\}', expr): ids.add(m.group(1))
        expr = LIT_RE.sub('""', expr)
        # positional args of format!/anyhow!/bail!
        for m in re.finditer(r'(?:format|anyhow|bail|write|writeln)!\s*\(', expr):
            e = find_matching(expr, m.end()-1, '(', ')')
            if e < 0: continue
            inner = expr[m.end():e]
            parts = split_args(inner)
            for part in parts[1:]:
                ids |= {i for i in IDENT_RE.findall(part) if i not in KEYWORDS}
        stripped = re.sub(r'"(?:[^"\\]|\\.)*"', '""', expr)
        stripped = re.sub(r'(?:format|anyhow|bail)!\s*\(.*', '', stripped, flags=re.S) if '!' in stripped else stripped
        for i in IDENT_RE.findall(stripped):
            if i not in KEYWORDS: ids.add(i)
        return ids

    def split_args(s):
        parts = []; depth = 0; cur = []; in_s = False; esc = False
        for c in s:
            if in_s:
                cur.append(c)
                if esc: esc = False
                elif c == '\\': esc = True
                elif c == '"': in_s = False
                continue
            if c == '"': in_s = True; cur.append(c); continue
            if c in '([{<': depth += 1
            elif c in ')]}>': depth -= 1
            if c == ',' and depth == 0: parts.append(''.join(cur)); cur = []
            else: cur.append(c)
        if cur: parts.append(''.join(cur))
        return [p.strip() for p in parts]

    # ----------------------------------------------------------- binding resolver
    memo = {}
    state = {'exhausted': False}
    visiting = set()      # (type, field) walks in progress — a From-impl construction recurses into itself
    TRACING_RE = re.compile(r'\b(?:tracing::)?(?:trace|debug|info|warn|error)!\s*\(')
    def strip_tracing(body):
        """Remove tracing macro invocations — a log is a different audience (TIER 2), not a sink."""
        out = []; i = 0
        while True:
            m = TRACING_RE.search(body, i)
            if not m: out.append(body[i:]); break
            e = find_matching(body, m.end()-1, '(', ')')
            out.append(body[i:m.start()])
            i = e + 1 if e > 0 else m.end()
        return ''.join(out)

    def resolve_ident(name, f, upto, depth, trail, side='err'):
        """Taint of identifier `name` at char offset `upto` inside fn f, resolved at its NEAREST
        preceding binding site (closure param, match arm, let, assignment, for, fn parameter)."""
        key = (f.file, f.body_start, name, upto, side)
        if key in memo: return memo[key]
        if depth > MAX_DEPTH: state['exhausted'] = True; return CLEAN
        saved = state['exhausted']; state['exhausted'] = False
        res = _resolve_ident(name, f, upto, depth, trail, side, key)
        if not state['exhausted']: memo[key] = res     # a verdict cut short by the depth cap is not a verdict
        else: memo.pop(key, None)
        state['exhausted'] = state['exhausted'] or saved
        return res

    def _resolve_ident(name, f, upto, depth, trail, side, key):
        text = files[f.file]['text']
        real = text[f.body_start:upto]
        # #3760 — binding SITES are searched on a literal-blanked copy so `source_id = ?1` inside a
        # SQL string or `x = y` inside a message is never mistaken for an assignment; the expressions
        # themselves are read from the real text at the same offsets (inline `{x}` names live in
        # literals and must survive).
        body = blank_tracing(blank_literals(real))
        nm = re.escape(name)
        full = text[f.body_start:f.end]
        def own_initializer(m):
            """#3760 — a `let name = <expr>` whose initializer CONTAINS the use being resolved is not
            its binding (`let events = { for e in events {..} kept }` reads the OUTER `events`)."""
            span_end = m.end() + len(expr_until(full, m.end(), stop_tokens=(';',)))
            return m.end() <= (upto - f.body_start) < span_end
        cands = []   # (position, kind, match)
        for mm in re.finditer(r'\.(map_err|or_else|unwrap_or_else|map|and_then|inspect_err|ok_or_else|filter_map)\s*\(\s*(?:move\s+)?\|\s*(?:mut\s+)?' + nm + r'\s*(?::[^|]*)?\|', body):
            cands.append((mm.start(), 'closure', mm))
        for mm in re.finditer(r'\b(Err|Ok|Some)\s*\(\s*(?:ref\s+)?(?:mut\s+)?' + nm + r'\s*\)\s*(?:if [^=]*)?=>', body):
            cands.append((mm.start(), 'arm', mm))
        for mm in re.finditer(r'\b([A-Z][A-Za-z0-9]*(?:::[A-Z][A-Za-z0-9]*)*)\s*\(\s*(?:ref\s+)?(?:mut\s+)?' + nm + r'\s*\)\s*(?:if [^=]*)?=>', body):
            if mm.group(1) not in ('Err', 'Ok', 'Some'): cands.append((mm.start(), 'typed-arm', mm))
        for mm in re.finditer(r'\b(?:if|while)?\s*let\s+(Err|Ok|Some)\s*\(\s*(?:ref\s+)?(?:mut\s+)?' + nm + r'\s*\)\s*=\s*', body):
            cands.append((mm.start(), 'let-pat', mm))
        for mm in re.finditer(r'\blet\s+(?:mut\s+)?' + nm + r'\s*(?::\s*[^=]+?)?\s*=\s*', body):
            if own_initializer(mm): continue
            cands.append((mm.start(), 'let', mm))
        for mm in re.finditer(r'(?<![A-Za-z0-9_.])' + nm + r'\s*=\s*(?!=)', body):
            if own_initializer(mm): continue
            cands.append((mm.start(), 'assign', mm))
        for mm in re.finditer(r'\bfor\s+(?:\(\s*\w+\s*,\s*)?' + nm + r'\)?\s+in\s+', body):
            cands.append((mm.start(), 'for', mm))
        res = CLEAN
        if cands:
            pos, kind, m = max(cands, key=lambda c: c[0])
            at = f.body_start + pos
            if kind == 'closure':
                recv = receiver_chain(real, m.start())
                cside = 'value' if m.group(1) in ('map', 'and_then', 'filter_map') else 'err'
                res = taint_expr(recv, f, at, depth + 1, trail + [f'{name}<-closure({m.group(1)})'], cside)
            elif kind == 'arm':
                subj = match_subject(real, m.start())
                if subj is not None:
                    res = taint_expr(subj, f, at, depth + 1, trail + [f'{name}<-{m.group(1)}(arm)'], 'err' if m.group(1) == 'Err' else 'value')
            elif kind == 'typed-arm':
                res = CLEAN   # payload of one of OUR typed enum variants
            elif kind == 'let-pat':
                expr = expr_until(real, m.end(), stop_tokens=(' else', '{', ';'))
                # #3760 — the expression is judged at ITS OWN offset (m.end()), not the `let`'s: a
                # `match` arm binding inside the initializer must be visible to the arm body's walk.
                res = taint_expr(expr, f, f.body_start + m.end(), depth + 1, trail + [f'{name}<-let {m.group(1)}'], 'err' if m.group(1) == 'Err' else 'value')
            elif kind in ('let', 'assign'):
                expr = expr_until(real, m.end(), stop_tokens=(';',))
                res = taint_expr(expr, f, f.body_start + m.end(), depth + 1, trail + [f'{name}<-{kind}'], side)
                # #3760 — a COLLECTION is produced by what is pushed into it, not by `Vec::new()`:
                # `let mut errors = Vec::new(); .. errors.push(format!("..{e}")); .. "errors": errors`
                # renders the pushed text. Every push/extend/insert between the binding and the
                # render is a producer; the first tainted one decides.
                if not res and COLLECTION_NEW_RE.match(expr.strip()):
                    for pm in re.finditer(r'(?<![A-Za-z0-9_.])' + nm + r'\.(push|push_str|extend|insert|append)\s*\(', body[m.end():]):
                        pat = m.end() + pm.start()
                        pe = find_matching(body, m.end() + pm.end() - 1, '(', ')')
                        if pe < 0: continue
                        args = split_args(real[m.end() + pm.end():pe])
                        if not args: continue
                        r = taint_expr(args[-1], f, f.body_start + pat, depth + 1, trail + [f'{name}<-{pm.group(1)}'], 'value')
                        if r: res = r; break
            elif kind == 'for':
                expr = expr_until(real, m.end(), stop_tokens=('{',))
                res = taint_expr(expr, f, f.body_start + m.end(), depth + 1, trail + [f'{name}<-for'], 'value')
            return res
        # function parameter -> call sites
        for idx, (pn, pt) in enumerate(f.params):
            if pn != name: continue
            if HANDLE_TYPES.search(pt) and not FOREIGN_TYPES.search(pt): return CLEAN
            if FOREIGN_TYPES.search(pt) and not re.search(r'dyn\s+(std::fmt::)?Display|impl\s+(std::fmt::)?Display', pt):
                res = T(kind_of_type(pt), f'param {name}: {pt}'); return res
            _tn = re.sub(r'^[&\s]*(?:mut\s+)?', '', pt).split('<')[0].split('::')[-1].strip()
            if side == 'err' and own_type_wraps_foreign(_tn): return T('db', f'param {name}: {pt} wraps a foreign payload')   # a VALUE of one of our types is our data (#3760)
            if not TEXTISH_TYPES.search(pt): return CLEAN   # a handle / struct, not text
            hb = strip_tracing(text[f.body_start:f.end])
            if CLEAN_RE.search(hb) or GUARD_RE.search(hb):
                return CLEAN     # a helper guarded by / rendering through a typed mapper
            res = callers_arg_taint(f, idx, depth + 1, trail + [f'{name}<-param#{idx} of {f.name}'], side)
            return res
        # struct field via self.name in a Display impl / method -> constructions of the impl type
        if f.impl_type and re.search(r'\bself\.' + nm + r'\b', body + text[upto:upto+200]):
            res = field_taint(f.impl_type, name, depth + 1, trail + [f'self.{name} of {f.impl_type}'])
            return res
        return CLEAN

    COLLECTION_NEW_RE = re.compile(r'^(?:Vec|String|HashMap|BTreeMap|HashSet|BTreeSet|VecDeque)(?:::<[^>]*>)?::(?:new|with_capacity|default)\s*\(|^vec!\s*\[|^Vec::<[^>]*>::new')

    def mapper_bound(name, f, upto):
        """Is `name`'s NEAREST `let`/assignment initializer (before `upto`) a render through a declared
        typed mapper (CLEAN_RE) — the one case where provenance outranks a name marker?"""
        text = files[f.file]['text']
        body = blank_tracing(blank_literals(text[f.body_start:upto]))
        nm = re.escape(name); last = None
        for mm in re.finditer(r'\blet\s+(?:mut\s+)?' + nm + r'\s*(?::\s*[^=]+?)?\s*=\s*|(?<![A-Za-z0-9_.])' + nm + r'\s*=\s*(?!=)', body):
            last = mm
        if last is None: return False
        init = expr_until(text[f.body_start:f.end], last.end(), stop_tokens=(';',))
        return CLEAN_RE.search(norm(LIT_RE.sub('""', init))) is not None

    def kind_of_type(pt):
        if re.search(r'reqwest', pt): return 'http'
        if re.search(r'io::Error', pt): return 'path'
        if re.search(r'ExecutorError|DecisionParseError', pt): return 'proc'
        return 'db'

    # #3767 — what may sit between a `}` and the start of the chain for that `}` to still be part of
    # the receiver: method-chain continuation only (`.name(..)`, `.name`, `?`, `.await`).
    CHAIN_TAIL_RE = re.compile(r'\s*(?:(?:\.[A-Za-z_][A-Za-z0-9_]*(?:::<[^>]*>)?(?:\([^;]*\))?|\?|\.await)\s*)*', re.S)
    def receiver_chain(body, at):
        """Text of the expression whose method chain ends at `at` (start of `.map_err`)."""
        i = at - 1; depth = 0
        while i >= 0:
            c = body[i]
            if c == '}' and depth == 0:
                # #3767 — a `}` at depth 0 is PART of the receiver only when the receiver is a method
                # chain hanging off that block (`match .. { .. }.map_err(..)`, `Foo { .. }.x()`,
                # `if c { a } else { b }.y()`): everything between the `}` and the chain start is
                # chain continuation. Any other expression text in between (`if .. { return
                # Err(..); }  crate::checkpoints::insert(conn, &cp)`) means the block is a PRECEDING
                # STATEMENT and the receiver starts after it. Scanning through it swallowed the
                # block's text into the receiver, and an OWN marker there (`..kind_authorized(`)
                # laundered the call that followed (checkpoint.rs:162 / share.rs:225 — #3766).
                if not CHAIN_TAIL_RE.fullmatch(body[i+1:at]): break
                depth += 1
            elif c in ')]}': depth += 1
            elif c in '([{':
                if depth == 0: break
                depth -= 1
            elif depth == 0 and c in ';=' and not (c == '=' and i > 0 and body[i-1] in '=!<>'):
                break
            elif depth == 0 and body[i-6:i+1].endswith('return'): break
            i -= 1
        return body[i+1:at]

    def match_subject(body, arm_at):
        """Find `match <subj> {` whose block contains arm_at; return subj text."""
        i = arm_at - 1; depth = 0
        while i >= 0:
            c = body[i]
            if c in ')]}': depth += 1
            elif c == '{':
                if depth == 0:
                    head_end = i
                    # walk back to 'match'
                    j = body.rfind('match', 0, head_end)
                    if j < 0: return None
                    subj = body[j+5:head_end]
                    # ensure no unbalanced block between
                    if subj.count('{') != subj.count('}'): return None
                    return subj.strip()
                depth -= 1
            elif c in '([':
                if depth > 0: depth -= 1
            i -= 1
        return None

    def expr_until(body, start, stop_tokens):
        """Text from `start` up to the first depth-0 stop token (';', ',', '}', ' else', '{')."""
        i = start; depth = 0; n = len(body); in_s = False; esc = False
        while i < n:
            c = body[i]
            if in_s:
                if esc: esc = False
                elif c == '\\': esc = True
                elif c == '"': in_s = False
                i += 1; continue
            if c == '"': in_s = True; i += 1; continue
            if depth == 0:
                for t in stop_tokens:
                    if body.startswith(t, i):
                        if t == '{' and not re.search(r'(\w|\)|>)\s*$', body[start:i]): continue   # `{` opening a block/struct literal
                        return body[start:i]
                if c in ')]}': return body[start:i]
            if c in '([{': depth += 1
            elif c in ')]}': depth -= 1
            i += 1
        return body[start:]

    CALL_RE = re.compile(r'^\s*((?:[A-Za-z_][A-Za-z0-9_]*::)*)([a-z_][a-z0-9_]*)\s*\((.*)\)\s*(?:\?|\.into\(\)|\.to_string\(\))?\s*$', re.S)
    SERDE_RE = re.compile(r'serde_json::to_|to_string_pretty|serde_json::from_|from_str\(|from_slice\(|from_reader\(|from_value\(')
    DOWNCAST_RE = re.compile(r'downcast_ref::<([A-Za-z0-9_:]+)>')
    def block_exits(block):
        """For a `{ ... }` body: the top-level `return <expr>` payloads and the tail expression, each as
        (offset-within-block, text). Brackets and string literals are respected, so a `;` inside a nested
        closure or a message literal does not split a statement."""
        inner = blank_literals(block)
        depth = 0; start = 1; stmts = []
        i = 1
        while i < len(inner) - 1:
            c = inner[i]
            if c in '([{': depth += 1
            elif c in ')]}': depth -= 1
            elif c == ';' and depth == 0:
                stmts.append((start, i)); start = i + 1
            i += 1
        exits = []
        # every `return <x>` in the block, at ANY brace depth (a return inside a nested `if { .. }`
        # still exits the closure); its payload runs to the first `;` at the return's own depth
        for rm in re.finditer(r'(?<![A-Za-z0-9_])return\b\s*', inner):
            j = rm.end(); d = 0
            while j < len(inner) - 1:
                c = inner[j]
                if c in '([{': d += 1
                elif c in ')]}':
                    if d == 0: break
                    d -= 1
                elif c == ';' and d == 0: break
                j += 1
            if block[rm.end():j].strip(): exits.append((rm.end(), block[rm.end():j]))
        tail = block[start:len(block)-1]
        if tail.strip(): exits.append((start, tail))
        return exits

    ERR_ADAPTER_RE = re.compile(r'\.(?:map_err|context|with_context|or_else|unwrap_or_else|inspect_err|ok_or_else|map_or_else)\s*\(')
    def strip_err_adapters(expr):
        out = expr
        for _ in range(12):
            m = ERR_ADAPTER_RE.search(out)
            if not m: break
            e = find_matching(out, m.end() - 1, '(', ')')
            if e < 0: break
            out = out[:m.start()] + out[e+1:]
        return out

    def taint_expr(expr, f, at, depth, trail, side='err'):
        if not expr: return CLEAN
        if depth > MAX_DEPTH: state['exhausted'] = True; return CLEAN
        st = expr.strip()
        # #3688/#3711 gate-7 finding — a BLOCK body (`.map_err(|e| { ...; format!(..) })`, an arm body)
        # renders only what its exits render: the tail expression and any top-level `return <x>`. The
        # statements before them are the tail's BINDING SITES, not evidence about what it renders.
        # Judging the whole block as one expression let a single OWN marker in any statement
        # (`e.classify()`, a `validate_*`, a `parse`) launder a `{text}` interpolated by the tail —
        # the shape that hid the peer body in `forward_to_http`'s parse-failure arm. Each exit is
        # judged at its OWN offset, so a `let` inside the block is still found by resolve_ident.
        if st.startswith('{') and st.endswith('}') and find_matching(st, 0, '{', '}') == len(st) - 1:
            base = at + expr.find(st)
            exits = block_exits(st)
            # #3760 — a block that INITIALISES a binding (`let x = { .. }`, a push argument) yields its
            # tail; a `return <y>` inside it leaves the FUNCTION and is judged where it is built (S1/S3
            # see it in the same fn). A CLOSURE body at a sink keeps every exit (#3711).
            if side == 'value' and exits and any(re.search(r'<-(?:let|assign|push|push_str|extend|insert|append)$', t) for t in trail):
                exits = exits[-1:] if not st[1:-1].rstrip().endswith(';') else []
                if not exits: return CLEAN   # a block with no tail has the unit value: nothing is rendered by it
            if exits:
                for (off, ex) in exits:
                    r = taint_expr(ex, f, base + off, depth + 1, trail + ['block-exit'], side)
                    if r: return r
                return CLEAN
        # #3760 — a VALUE is what the Ok/success side carries; the adapters that only SHAPE the error
        # (`.map_err(|e| ..)`, `.context(..)`, `.or_else(..)`, `.unwrap_or_else(..)`) are stripped
        # before the identifier walk, or the closure's `|e|` reads as a rendered ident and every
        # `let x = store_call().map_err(..)?` value inherits the driver's error taint.
        if side == 'value':
            st = strip_err_adapters(st); expr = st
            # a struct LITERAL of ours is our own construction; its fields are judged when rendered (#3760)
            if re.match(r'^\s*&?(?:[A-Za-z_][A-Za-z0-9_]*::)*[A-Z][A-Za-z0-9]*\s*\{', st) and st.endswith('}'): return CLEAN
            # A mapped collection's VALUE is what the closure produces (`f.peers.iter().map(|p|
            # peer_status(&p.id, ..)).collect()` renders `peer_status`'s result, not `peers`): judge
            # the LAST `.map(|..| body)` closure body as the value.
            mv = None
            for mm_ in re.finditer(r'\.map\s*\(\s*(?:move\s+)?\|[^|]*\|\s*', st):
                e_ = find_matching(st, st.rfind('(', 0, mm_.end()), '(', ')') if False else find_matching(st, mm_.start() + st[mm_.start():].find('('), '(', ')')
                if e_ > 0: mv = (mm_.end(), e_)
            if mv:
                return taint_expr(st[mv[0]:mv[1]], f, at + expr.find(st[mv[0]:mv[1]]), depth + 1, trail + ['map-closure-value'], 'value')
        mm = re.match(r'match\s+(.+?)\s*\{', st, re.S)
        if mm and st.endswith('}'):
            # #3760 — a match EXPRESSION's value is what its ARMS produce: `Err(e) => format!("..{e}")`
            # renders the error even when the subject is a db call whose VALUE side is our own data.
            # Each arm body is judged at its own offset (its pattern binding precedes it), then the
            # subject decides what is left.
            base = at + expr.find(st)
            ob = st.find('{', mm.end() - 1); cb = find_matching(st, ob, '{', '}')
            inner = blank_literals(st[ob+1:cb]); pos = 0
            while True:
                am = inner.find('=>', pos)
                if am < 0: break
                j = am + 2
                while j < len(inner) and inner[j] in ' \t\n': j += 1
                if j < len(inner) and inner[j] == '{':
                    be = find_matching(inner, j, '{', '}'); body_txt = st[ob+1+j:ob+1+be+1]; pos = be + 1
                else:
                    body_txt = expr_until(inner, j, stop_tokens=(',',)); body_txt = st[ob+1+j:ob+1+j+len(body_txt)]; pos = j + len(body_txt) + 1
                if body_txt.strip():
                    # a `return ..` arm leaves the fn: it is not the match's VALUE (judged where it is built)
                    if side == 'value' and re.match(r'\s*(?:return\b|continue\b|break\b)', body_txt) and any(re.search(r'<-(?:let|assign|push|push_str|extend|insert|append)$', t) for t in trail): continue
                    r = taint_expr(body_txt, f, base + ob + 1 + j, depth + 1, trail + ['match-arm'], side)
                    if r: return r
            return taint_expr(mm.group(1), f, at, depth + 1, trail + ['match-subject'], side)
        mm = re.match(r'(?:if|while)\s+let\s+(?:Ok|Some)\s*\([^)]*\)\s*=\s*(.+?)\s*\{', st, re.S)
        if mm: return taint_expr(mm.group(1), f, at, depth + 1, trail + ['if-let-subject'], side)
        # `e.field` on a parameter of one of OUR struct types: walk that struct's field constructions
        fm = re.match(r'^\s*&?([a-z_][a-z0-9_]*)\.([a-z_][a-z0-9_]*)\s*(?:\.(?:clone|to_string|as_str|to_owned)\(\))?\s*$', st)
        if fm and f is not None:
            for (pn, pt) in f.params:
                if pn == fm.group(1) and not FOREIGN_TYPES.search(pt) and not HANDLE_TYPES.search(pt):
                    tn = re.sub(r'^[&\s]*(?:mut\s+)?', '', pt).split('<')[0].split('::')[-1].strip()
                    if tn[:1].isupper():
                        return field_taint(tn, fm.group(2), depth + 1, trail + [f'{pn}.{fm.group(2)} of {tn}'])
        dm = DOWNCAST_RE.search(st)
        if dm:   # a downcast yields the named type: foreign iff the type is
            return T(kind_of_type(dm.group(1)), f'downcast to {dm.group(1)} @ ' + '>'.join(trail)) if FOREIGN_TYPES.search(dm.group(1)) else CLEAN
        expr_nl = norm(LIT_RE.sub('""', expr))
        if side == 'err' and SERDE_RE.search(expr_nl.split('(', 1)[0] + '('): return CLEAN   # a serde ERROR (at the call HEAD) carries line/col only
        # a call to one of OUR functions: the callee decides (return error type, which params it renders)
        cm = CALL_RE.match(expr_nl)
        # #3711 — crate::url_display::* is a SANITISATION BOUNDARY, not a transparent text->text
        # helper: reducing a URL to scheme/host/path is precisely the cleansing a taint tracker
        # must honour (the gate-2 lesson). When a value passes THROUGH url_display the taint STOPS
        # here — never walk to the argument. Provenance/module-path anchored (not a binding name),
        # so renaming a local cannot re-arm or disarm it. Specific to this module: a generic
        # redact_/prefix/msg helper stays transparent (RED) per the masker/wrapper controls.
        if cm and re.search(r'(?:^|::)url_display::$', cm.group(1) or ''):
            return CLEAN
        # #3760 — a DECLARED typed mapper (`mapper=<fn>` in the ledger, or the built-in set) is a
        # rendering boundary by declaration: its output is caller-safe, so the walk never enters it
        # to re-judge its arguments (the same stop the url_display module gets by module path).
        if cm and CLEAN_RE.search(cm.group(2) + '('):
            return CLEAN
        if cm:   # a single call only when its parentheses are the OUTERMOST pair (not `a(..).b(..)`)
            op = expr_nl.find('(', cm.start(2)); cl = find_matching(expr_nl, op, '(', ')')
            if cl < 0 or expr_nl[cl+1:].strip() not in ('', '?', '.into()', '.to_string()'): cm = None
        if cm and cm.group(2) not in ('format', 'vec', 'json', 'anyhow', 'bail', 'ensure', 'write', 'writeln', 'matches'):
            g = find_fn(cm.group(2), f.file, cm.group(1))
            if g:
                args = split_args(cm.group(3))
                r = call_taint(g[0], args, f, at, depth + 1, trail + [f'call {cm.group(1)}{cm.group(2)}()'], side)
                if r is not None: return r
        # `recv.method(args)` where `method` is a UNIQUE impl method of ours: the method decides
        mm = re.match(r'^\s*([a-z_][a-z0-9_]*)\.([a-z_][a-z0-9_]*)\s*\(', expr_nl)
        if mm:
            op = expr_nl.find('(', mm.start(2)); cl = find_matching(expr_nl, op, '(', ')')
            if cl > 0 and expr_nl[cl+1:].strip() in ('', '?', '.into()', '.to_string()', '.await', '.await?'):
                ms = [c for c in fns_by_name.get(mm.group(2), []) if c.impl_type]
                if len(ms) == 1 and not [c for c in fns_by_name.get(mm.group(2), []) if not c.impl_type]:
                    r = call_taint(ms[0], split_args(expr_nl[op+1:cl]), f, at, depth + 1, trail + [f'call .{mm.group(2)}()'], side)
                    if r is not None and r: return r
        # #3760 — provenance before names: a BARE identifier is judged by its binding (a `peers`
        # local built from `peer_status(..)` projections is what it was bound to, not what it is
        # called); the name markers decide only when nothing binds it.
        bm = re.match(r'^\s*&?\s*(?:mut\s+)?([a-z_][a-z0-9_]*)\s*(?:\.(?:clone|to_string|as_str|to_owned|as_ref)\(\))?\s*$', expr)
        if bm and f is not None and bm.group(1) not in KEYWORDS:
            r = resolve_ident(bm.group(1), f, at, depth + 1, trail, side)
            if r: return r
            # Only a binding whose initializer renders through a DECLARED typed mapper outranks the
            # name marker (`let peers = ..map(|p| peer_status(..)).collect()`); a `store_label` bound
            # to anything else keeps its marker (#3674 stays tracked).
            if mapper_bound(bm.group(1), f, at): return CLEAN
        c = classify_expr(expr, side)
        if c is CLEAN: return CLEAN
        if c: return T(c.kind, c.why + ' @ ' + '>'.join(trail))
        # unknown: follow identifiers, then any embedded calls to our own functions
        # Deterministic order: `rendered_idents` is a set, and the FIRST tainted identifier names the
        # finding's source kind. Iterating the raw set let one site key as `:http` on one run and
        # `:dsn` on the next (PYTHONHASHSEED), which no ledger can track. Alphabetical is the fixed
        # tie-break; a site that renders several foreign values keys on the first by name.
        # #3760 — an identifier the expression binds ITSELF (a closure parameter `|e|`, an arm binding
        # `Err(e) =>` / `Some(x) =>`, an inner `let x`) is not resolved at the expression's start: the
        # binding that precedes the expression is a different, shadowed variable.
        inner_bound = set()
        for cm_ in re.finditer(r'\|([^|]*)\|', expr):
            for part in cm_.group(1).split(','):
                mm_ = re.match(r'\s*(?:\(\s*)?(?:mut\s+)?(?:ref\s+)?([a-z_][a-z0-9_]*)', part)
                if mm_: inner_bound.add(mm_.group(1))
        inner_bound |= set(re.findall(r'\b(?:Ok|Err|Some)\s*\(\s*(?:ref\s+)?(?:mut\s+)?([a-z_][a-z0-9_]*)\s*\)\s*=>', expr))
        inner_bound |= set(re.findall(r'\blet\s+(?:mut\s+)?([a-z_][a-z0-9_]*)\b', expr))
        inner_bound |= set(re.findall(r'\bfor\s+(?:mut\s+)?([a-z_][a-z0-9_]*)\s+in\b', expr))
        for name in sorted(rendered_idents(expr)):
            if name in inner_bound: continue
            r = resolve_ident(name, f, at, depth + 1, trail, side)
            if r: return r
        for m in re.finditer(r'(?<![A-Za-z0-9_.])((?:[A-Za-z_][A-Za-z0-9_]*::)*)([a-z_][a-z0-9_]*)\s*\(', expr_nl):
            callee = m.group(2)
            if callee in ('format', 'vec', 'json', 'println', 'eprintln', 'write', 'writeln', 'anyhow', 'bail', 'ensure', 'lock', 'clone', 'unwrap', 'ok', 'err', 'as_ref', 'as_str', 'to_string', 'into', 'matches'): continue
            e = find_matching(expr_nl, m.end()-1, '(', ')')
            args = split_args(expr_nl[m.end():e]) if e > 0 else []
            g = find_fn(callee, f.file, m.group(1))
            if not g: continue
            r = call_taint(g[0], args, f, at, depth + 1, trail + [f'call {callee}()'], side)
            if r: return r
        return CLEAN

    ERR_TYPE_RE = re.compile(r'->\s*(?:std::)?(?:result::)?Result<(.*)>\s*$', re.S)
    FOREIGN_ERR_TYPE = re.compile(r'anyhow|rusqlite|sqlx|StoreError|StoreResult|Box<dyn|\bString\b|&str|io::Error|reqwest|BoxBackendError|ExecutorError|MemoryError')
    ENUM_DEFS = {}   # TypeName -> enum body text (crate-wide), to see what an own error type WRAPS
    for _p, _d in files.items():
        for _m in re.finditer(r'\b(?:pub(?:\([a-z]+\))?\s+)?enum\s+([A-Z][A-Za-z0-9]*)\s*(?:<[^{]*>)?\s*\{', _d['text']):
            _e = find_matching(_d['text'], _m.end()-1, '{', '}')
            if _e > 0: ENUM_DEFS[_m.group(1)] = _d['text'][_m.end():_e]
    def own_type_wraps_foreign(tn):
        """An enum of ours whose variant carries anyhow / rusqlite / sqlx / StoreError / Box<dyn Error> text
        (`QuotaCheckError::Sql(anyhow::Error)`) is foreign-capable through its Display."""
        body = ENUM_DEFS.get(tn)
        return bool(body and FOREIGN_ERR_TYPE.search(body))
    def callee_err_class(g):
        """'own' if g returns Result<_, OurTypedError>; 'foreign' if its error type can carry driver/peer text; None if unknown."""
        sig = g.sig.replace('\n', ' ')
        m = re.search(r'->\s*(.+?)\s*(?:where\b.*)?$', sig, re.S)
        if not m: return None
        ret = m.group(1).strip()
        if re.search(r'\bStoreResult\b|rusqlite::Result|sqlx::Result|reqwest::Result|io::Result', ret): return 'driver'   # the error IS the driver's type
        if re.search(r'anyhow::Result|\bResult<[^,<>]*>\s*$', ret): return 'foreign'
        rm = re.search(r'Result<(.*)>', ret, re.S)
        if not rm: return None
        parts = split_args(rm.group(1))
        if len(parts) < 2: return 'foreign'
        et = parts[1]
        if re.search(r'rusqlite|sqlx|reqwest|StoreError|io::Error', et): return 'driver'
        if FOREIGN_ERR_TYPE.search(et): return 'foreign'
        if re.match(r'^[A-Za-z_][\w:]*(<.*>)?$', et.strip()):
            return 'foreign' if own_type_wraps_foreign(et.strip().split('<')[0].split('::')[-1]) else 'own'
        return None

    def classify_body(body, side):
        """Whole-fn-body scan: any foreign producer anywhere makes the fn's text foreign-capable
        (an OWN marker elsewhere in the body does not launder it)."""
        b = norm(LIT_RE.sub('""', body))
        for kind, rx in FOREIGN:
            if side == 'value' and kind == 'db': continue
            m = rx.search(b)
            if m: return T(kind, m.group(0))
        return CLEAN

    site_memo = {}
    def callee_err_sites(g, body, f, at, depth, trail):
        key = (g.file, g.body_start)
        if key in site_memo: return site_memo[key]
        if key in visiting: return CLEAN
        visiting.add(key)
        try:
            r = _callee_err_sites(g, body, f, at, depth, trail)
        finally: visiting.discard(key)
        if not state['exhausted']: site_memo[key] = r
        return r

    def blank_literals(t):
        """Replace every string literal's CONTENT with spaces (length-preserving), so `?`, `=` and `;`
        inside SQL / messages cannot be mistaken for operators."""
        return LIT_RE.sub(lambda m: '"' + ' ' * (len(m.group(0)) - 2) + '"', t)

    def blank_tracing(t):
        """Blank every tracing macro invocation (length-preserving, newlines kept): a log is another
        audience, and its `field = %value` syntax is not an assignment a binding search may pick up
        (#3760: `source_id = %source_id` inside `tracing::warn!` read as `source_id<-assign`)."""
        out = []; i = 0
        while True:
            m = TRACING_RE.search(t, i)
            if not m: out.append(t[i:]); break
            e = find_matching(t, m.end()-1, '(', ')')
            if e < 0: out.append(t[i:]); break
            out.append(t[i:m.start()]); out.append(re.sub(r'[^\n]', ' ', t[m.start():e+1]))
            i = e + 1
        return ''.join(out)

    def _callee_err_sites(g, body, f, at, depth, trail):
        body = blank_literals(body)
        """Foreign iff one of g's error-producing sites is: a `?` whose statement classifies foreign on the
        err side, or an explicit `Err(<x>)` whose payload is foreign. A callee that only ever constructs its
        own variants from its own state (`Err(StorageError::RecordStopped { .. })`) is own."""
        # `?` propagation (any `?` — comments and strings are already stripped), `return <expr>`, and the
        # tail expression: the statement text from the last statement boundary up to the operator
        def stmt_before(j):
            """The statement ending at j, scanned BACKWARDS across balanced brackets (a `?` after a
            multi-line closure argument still sees the call it is attached to)."""
            i = j - 1; depth = 0
            while i >= 0:
                c = body[i]
                if c in ')]}': depth += 1
                elif c in '([{':
                    if depth == 0: break
                    depth -= 1
                elif depth == 0 and (c == ';' or (c == '=' and body[i-1:i] not in ('=', '!', '<', '>') and body[i+1:i+2] not in ('=', '>'))): break
                i -= 1
            return body[i+1:j]
        cands = [m.start() for m in re.finditer(r'\?', body)]
        for m in re.finditer(r'\breturn\s+', body):
            e = body.find(';', m.end()); cands.append(e if e > 0 else len(body))
        # tail: the last non-empty statement without a trailing `;` inside the outermost braces
        tail = body.rstrip()                         # the slice excludes the fn's closing brace
        if tail and tail[-1] not in ';}{':
            cands.append(len(tail))
        for j in cands:
            stmt = stmt_before(j)
            if not stmt.strip(): continue
            c = classify_expr(stmt, 'err')
            if c: return T(c.kind, c.why + ' propagated in ' + g.name + ' @ ' + '>'.join(trail))
            for mm in re.finditer(r'(?<![A-Za-z0-9_.])((?:[A-Za-z_][A-Za-z0-9_]*::)*)([a-z_][a-z0-9_]*)\s*\(', norm(LIT_RE.sub('""', stmt))):
                h = find_fn(mm.group(2), g.file, mm.group(1))
                if h and h[0] is not g and callee_err_class(h[0]) == 'driver':
                    return T(kind_of_type(h[0].sig), f'{h[0].name}() returns the driver\'s own error type, forwarded by {g.name} @ ' + '>'.join(trail))
                if h and h[0] is not g and callee_err_class(h[0]) != 'own' and depth < MAX_DEPTH:
                    r = callee_err_sites(h[0], strip_tracing(files[h[0].file]['text'][h[0].body_start:h[0].end]), f, at, depth + 1, trail + [f'{h[0].name}()'])
                    if r: return r
        # explicit Err(..) constructions
        for m in re.finditer(r'\bErr\s*\(', body):
            e = find_matching(body, m.end()-1, '(', ')')
            if e < 0 or body[e+1:e+4].lstrip().startswith('=>'): continue
            inner = body[m.end():e].strip()
            if re.match(r'^[a-z_][a-z0-9_]*$', inner) and body[e+1:e+4].lstrip().startswith('=>'): continue
            r = taint_expr(inner, g, g.body_start + m.start(), depth + 1, trail + [f'Err(..) in {g.name}'], 'value')
            if r: return r
        return CLEAN

    def call_taint(g, args, f, at, depth, trail, side):
        """Taint of a call to our own fn g. Returns None when it cannot decide."""
        body = strip_tracing(files[g.file]['text'][g.body_start:g.end])
        if side == 'err':
            ec = callee_err_class(g)
            if ec == 'own': return CLEAN
            if g.file == 'src/validate.rs': return CLEAN     # the validation module speaks only about the caller's own input
            if ec == 'driver': return T(kind_of_type(g.sig), f'{g.name}() returns the driver\'s own error type @ ' + '>'.join(trail))
            # error type String / anyhow / an own enum that CAN wrap a driver error: judged at the callee's
            # own Err SITES — a `?` propagated from a foreign producer, or an `Err(..)` built from one.
            c = callee_err_sites(g, body, f, at, depth, trail)
            if c is CLEAN:
                # errors built from the callee's own params (a validator returning Err(String)) inherit the args
                for idx, (pn, pt) in enumerate(g.params):
                    if idx >= len(args): break
                    if re.search(r'\{' + re.escape(pn) + r'[:}]|\b' + re.escape(pn) + r'\.(to_string|display|as_str|clone)\(\)', body):
                        r = taint_expr(args[idx], f, at, depth + 1, trail + [f'arg#{idx}->{g.name}.{pn}'], 'value')
                        if r: return r
                return CLEAN
            return T(c.kind, c.why + ' in ' + g.name + ' @ ' + '>'.join(trail))
        # value side. A text -> text helper that is NOT a declared typed mapper is TRANSPARENT: masking,
        # trimming, prefixing or "redacting" a foreign string does not make it ours (the gate-2 lesson).
        sig = g.sig.replace('\n', ' ')
        rm = re.search(r'->\s*(.+?)\s*$', sig)
        ret = rm.group(1) if rm else ''
        if re.search(r'^(?:&\s*)?(?:String|str|Cow<|std::borrow::Cow<|Option<String>|Result<String|PathBuf|Path\b|Result<PathBuf|Option<PathBuf)', ret.strip()) and not CLEAN_RE.search(g.name + '('):
            for idx, (pn, pt) in enumerate(g.params):
                if idx >= len(args): break
                if re.search(r'&?\s*(str|String|Cow<|impl\s+(std::fmt::)?Display|&dyn\s+(std::fmt::)?Display|Display|Path\b|PathBuf|AsRef<Path>)', pt):
                    r = taint_expr(args[idx], f, at, depth + 1, trail + [f'arg#{idx}->{g.name}.{pn} (text->text helper is transparent)'], 'value')
                    if r: return r
        if CLEAN_RE.search(body) and not re.search(r'\{[a-z_]+[:}]', body): return CLEAN
        rendered_any = False
        # #3760 — a filesystem PROBE consumes a path and yields a size / a flag, never the path's
        # text: `std::fs::metadata(db_path).len()` in `stats` does not render `db_path`.
        probe_body = re.sub(r'\b(?:std::fs::|fs::)?(?:metadata|symlink_metadata|exists|is_file|is_dir|read_dir|remove_file|create_dir_all|try_exists)\s*\(\s*&?\s*([a-z_][a-z0-9_]*)\s*\)', r'probe(\1_)', body)
        probe_body = re.sub(r'\b([a-z_][a-z0-9_]*)\.(?:exists|is_file|is_dir|metadata|symlink_metadata|try_exists)\(\)', r'\1_.probe()', probe_body)
        for idx, (pn, pt) in enumerate(g.params):
            if idx >= len(args): break
            if re.search(r'\{' + re.escape(pn) + r'[:}]|\b' + re.escape(pn) + r'\.(to_string|display|as_str|clone|to_owned)\(\)|\b' + re.escape(pn) + r'\b\s*[,)]|\bformat!\([^;]*\b' + re.escape(pn) + r'\b', probe_body):
                rendered_any = True
                r = taint_expr(args[idx], f, at, depth + 1, trail + [f'arg#{idx}->{g.name}.{pn}'], 'value')
                if r: return r
        # a callee that RETURNS TEXT may build it from what its body reads (a config value, a path)
        if re.search(r'^(?:&\s*)?(?:String|str|Cow<|std::borrow::Cow<|Option<String>|Result<String|PathBuf|Path\b|Result<PathBuf|Option<PathBuf)', ret.strip()):
            c = classify_body(body, 'value') if len(body) < 2500 else CLEAN
            if c: return T(c.kind, c.why + ' in ' + g.name + ' @ ' + '>'.join(trail))
        return CLEAN

    def find_fn(callee, from_file, path=''):
        """Resolve a call to our own fn. `path` is the `a::b::` qualifier (may be empty)."""
        cands = fns_by_name.get(callee, [])
        if not cands: return []
        segs = [x for x in path.strip(':').split('::') if x and x not in ('crate', 'self', 'super')]
        if segs:
            tail = segs[-1]
            by_mod = [c for c in cands if re.search(r'(^|/)' + re.escape(tail) + r'(\.rs|/mod\.rs)$', c.file) or (tail == 'db' and c.file.startswith('src/storage/'))]
            # #3767 — the module ROOT (`<tail>/mod.rs`, `src/storage/mod.rs` for the `db` alias) is the fn the
            # qualifier names; a sibling file's same-named fn is a different function.
            by_mod.sort(key=lambda c: (not c.file.endswith('/mod.rs'), c.file))
            if by_mod: return by_mod[:1]
            if tail[:1].isupper():   # Type::method — an inherent/impl method
                by_impl = [c for c in cands if c.impl_type == tail]
                if by_impl: return by_impl[:1]
            return cands[:1] if len(cands) == 1 else []   # a re-export: unique name across the crate resolves
        same = [c for c in cands if c.file == from_file]
        if same: return same[:1]
        return cands[:1] if len({c.file for c in cands}) == 1 else []

    def callers_arg_taint(g, idx, depth, trail, side='value'):
        """Taint of argument #idx across the crate's call sites of g. A call site counts only when it
        is path-qualified with g's module or impl type, a bare call inside g's own file, or — for a
        method whose name is unique among impls — an `x.name(` method call."""
        if depth > MAX_DEPTH: state['exhausted'] = True; return CLEAN
        if sum(1 for t in trail if '<-param#' in t) > 3: state['exhausted'] = True; return CLEAN
        mod_tail = re.sub(r'\.rs$', '', os.path.basename(g.file))
        if mod_tail == 'mod': mod_tail = os.path.basename(os.path.dirname(g.file))
        unique_method = bool(g.impl_type) and sum(1 for c in fns_by_name.get(g.name, []) if c.impl_type) == 1
        seen = 0
        for (p, pos, qualifier, is_method) in CALL_SITES.get(g.name, []):
            text = files[p]['text']
            if is_method:
                if not unique_method: continue
            else:
                qual = qualifier.strip(':').split('::')[-1] if qualifier else ''
                if qual:
                    if qual not in (mod_tail, g.impl_type, 'db' if g.file.startswith('src/storage/') else None): continue
                elif p != g.file or g.impl_type: continue
            op = text.find('(', pos); e = find_matching(text, op, '(', ')')
            if e < 0: continue
            args = split_args(text[op+1:e])
            if idx >= len(args): continue
            cf = enclosing_fn(p, pos)
            if cf is None or cf is g: continue
            seen += 1
            if seen > 40: state['exhausted'] = True; return CLEAN
            r = taint_expr(args[idx], cf, pos, depth + 1, trail + [f'{p}:{line_of(text, pos)}'], side)
            if r: return r
        return CLEAN

    def field_taint(type_name, field, depth, trail):
        """Taint of `field` across every construction `Type { .., field: expr }` / shorthand."""
        if depth > MAX_DEPTH: state['exhausted'] = True; return CLEAN
        if (type_name, field) in visiting: return CLEAN
        visiting.add((type_name, field))
        try: return _field_taint(type_name, field, depth, trail)
        finally: visiting.discard((type_name, field))

    def _field_taint(type_name, field, depth, trail):
        sites = [(p, pos, False) for (p, pos) in CONSTRUCTIONS.get(type_name, [])] + [(p, pos, True) for (p, pos) in SELF_CONSTRUCTIONS]
        for (p, pos, is_self) in sites:
            text = files[p]['text']
            cf = enclosing_fn(p, pos)
            if is_self and (cf is None or cf.impl_type != type_name): continue
            b = text.find('{', pos); e = find_matching(text, b, '{', '}')
            if e < 0: continue
            inner = text[b+1:e]
            if '=>' in inner[:3] or re.match(r'\s*\.\.', inner): continue
            if cf is None: continue
            for part in split_args(inner):
                mm = re.match(r'\s*' + re.escape(field) + r'\s*(?::\s*(.+))?$', part, re.S)
                if not mm: continue
                expr = mm.group(1) if mm.group(1) else field
                r = taint_expr(expr, cf, pos, depth + 1, trail + [f'{type_name}{{{field}}}@{p}:{line_of(text, pos)}'], 'value')
                if r: return r
        return CLEAN

    # ------------------------------------------------------------------- sinks
    findings = []
    def add(sev, key, file, line, fn, text):
        findings.append({'sev': sev, 'key': key, 'file': file, 'line': line, 'fn': fn, 'text': text})

    def json_values(text, jstart):
        """Every VALUE of a `json!( .. )` invocation starting at `jstart`, at ANY key and any nesting
        (objects and arrays), as (expr, char_idx). Key-agnostic: a caller reads `"errors"`, `"detail"`,
        `"note"` and `"warnings"` exactly as it reads `"error"` (#3760)."""
        op = text.find('(', jstart)
        if op < 0: return
        e = find_matching(text, op, '(', ')')
        if e < 0: return
        yield from _json_walk(text, op + 1, e)
    def _json_walk(text, a, b):
        seg = text[a:b]; st = seg.lstrip(); off = a + (len(seg) - len(st))
        if st.startswith('{'):
            ce = find_matching(st, 0, '{', '}')
            if ce < 0: return
            body = st[1:ce]; pos = 0
            for part in split_args(body):
                if not part: continue
                idx = body.find(part, pos); pos = idx + len(part)
                km = re.match(r'\s*(?:"(?:[^"\\]|\\.)*"|\([^)]*\)|[A-Za-z_][A-Za-z0-9_:.]*)\s*:\s*', part, re.S)
                if not km: continue
                yield from _json_walk(text, off + 1 + idx + km.end(), off + 1 + idx + len(part))
        elif st.startswith('['):
            ce = find_matching(st, 0, '[', ']')
            if ce < 0: return
            body = st[1:ce]; pos = 0
            for part in split_args(body):
                if not part: continue
                idx = body.find(part, pos); pos = idx + len(part)
                yield from _json_walk(text, off + 1 + idx, off + 1 + idx + len(part))
        elif st.strip():
            yield (st.rstrip(), off)

    def sink_exprs_in(p):
        """Yield (kind, expr, char_idx) for every caller-facing sink in file p. The sink FUNCTIONS
        are the derived sets HTTP_FNS / MCP_FNS (#3760); the shapes inside them are judged by value."""
        text = files[p]['text']
        if p.startswith('src/cli/') or p.startswith('src/bin/') or p == 'src/main.rs':
            # operator audience (TIER 2) — EXCEPT the PreToolUse decision line, which the AI host reads
            for m in re.finditer(r'\bPretoolDecision\s*\{', text):
                e = find_matching(text, m.end()-1, '{', '}')
                if e < 0: continue
                for part in split_args(text[m.end():e]):
                    mm = re.match(r'\s*reason\s*(?::\s*(.+))?$', part, re.S)
                    if mm: yield ('deny-reason', mm.group(1) or 'reason', m.start())
            return
        def in_sink_def(idx):
            ef = enclosing_fn(p, idx)
            return ef is not None and ef.name in ('store_err_to_response', 'err_response')
        def in_http(idx):
            ef = enclosing_fn(p, idx)
            return ef is not None and (ef.file, ef.name) in HTTP_FNS
        def in_mcp(idx):
            ef = enclosing_fn(p, idx)
            return ef is not None and (ef.file, ef.name) in MCP_FNS
        # S1: every value of every json!(..) built inside a derived HTTP fn (any key, any nesting), and
        #     every value of an `Ok(json!(..))` / bare `json!(..)` payload built inside a derived MCP fn.
        for m in re.finditer(r'\bjson!\s*\(', text):
            if in_sink_def(m.start()): continue
            if in_http(m.start()): kind = 'http-body'
            elif in_mcp(m.start()): kind = 'mcp-result'
            else: continue
            for (expr, at) in json_values(text, m.start()):
                if LIT_RE.fullmatch(expr.strip()) or re.fullmatch(r'\s*(?:true|false|null|-?\d+(?:\.\d+)?)\s*', expr): continue
                yield (kind, expr, at)
        # S0: the SAFE FUNNELS — counted so a run can prove it saw them and flagged none
        for m in re.finditer(r'\b(store_err_to_response|handler_error_500|sanitize_store_err_message|sanitize_bulk_row_error)\s*\(', text):
            yield ('funnel', m.group(1) + '(', m.start())
        # S2: err_response(<expr>)  (handler helper: single String; mcp: (id, code, message))
        for m in re.finditer(r'\berr_response\s*\(', text):
            e = find_matching(text, m.end()-1, '(', ')')
            if e < 0: continue
            args = split_args(text[m.end():e])
            if not args: continue
            yield ('http-body' if p.startswith('src/handlers') else 'rpc-error', args[-1], m.start())
        # S3: (StatusCode::X, <text-expr>) tuple responses (not Json) inside a derived HTTP fn
        for m in re.finditer(r'\(\s*StatusCode::[A-Z_]+\s*,\s*', text):
            if not in_http(m.start()): continue
            e = find_matching(text, m.start(), '(', ')')
            if e < 0: continue
            if in_sink_def(m.start()): continue   # the funnel is judged arm-by-arm; err_response's callers are the sinks
            rest = text[m.end():e].strip()
            if rest.startswith('Json') or rest.startswith('[') or rest.startswith('axum') or rest.startswith('headers') or rest.startswith('(') : continue
            yield ('http-body', rest, m.start())
        # S4: MemoryError text variants / Self::DatabaseError(...) in errors.rs
        for m in re.finditer(r'\b(?:MemoryError|Self)::(DatabaseError|ValidationFailed|Conflict|NotFound|RefusedByGovernance|Internal)\s*\(', text):
            e = find_matching(text, m.end()-1, '(', ')')
            if e < 0: continue
            yield ('memory-error', text[m.end():e], m.start())
        # S5: MCP tool errors — Err(...) / map_err(|e| ...) inside a derived MCP fn (the wire error is String)
        for m in re.finditer(r'\bErr\s*\(', text):
            if not in_mcp(m.start()): continue
            e = find_matching(text, m.end()-1, '(', ')')
            if e < 0: continue
            inner = text[m.end():e].strip()
            # skip patterns (Err(e) =>), and skip if this is inside a From impl (covered by S4)
            after = text[e+1:e+4]
            if after.lstrip().startswith('=>') or re.match(r'^[a-z_][a-z0-9_]*$', inner) and after.lstrip().startswith('=>'): continue
            # #3713 — `let Err(e) = ..` / `if let Err(e) = ..` / `while let Err(e) = ..` is a PATTERN too,
            # not a re-raise expression: the ident it binds goes wherever the block sends it (usually a
            # tracing line). Reading it as `Err(e)`-the-value made six log-only sites under src/mcp
            # FAIL with "expr: e" while the value never reached a caller. `==` stays an expression.
            if after.lstrip().startswith('=') and not after.lstrip().startswith('=='): continue
            yield ('mcp-error', inner, m.start())
        for m in re.finditer(r'\.map_err\s*\(\s*\|\s*(?:mut\s+)?([a-z_][a-z0-9_]*)\s*(?::[^|]*)?\|\s*', text):
            if not in_mcp(m.start()): continue
            e = find_matching(text, m.start() + len('.map_err'), '(', ')')
            if e < 0: continue
            yield ('mcp-error', text[m.end():e], m.end())
        # S6: Deny { reason: <expr> } / PretoolDecision { reason } — a refusal renderer by SHAPE, wherever it lives
        for m in re.finditer(r'\b(?:Deny|PretoolDecision)\s*\{', text):
            e = find_matching(text, m.end()-1, '{', '}')
            if e < 0: continue
            inner = text[m.end():e]
            if '=>' in text[e+1:e+5]: continue
            for part in split_args(inner):
                mm = re.match(r'\s*reason\s*(?::\s*(.+))?$', part, re.S)
                if mm: yield ('deny-reason', mm.group(1) or 'reason', m.start())

    # S7: functions whose Err(String) is persisted into a caller-readable record
    RECORD_FNS = set()
    for p, d in files.items():
        text = d['text']
        for m in re.finditer(r'\blast_error\s*(?:=|:)\s*([a-z_][a-z0-9_]*)\b', text):
            cf = enclosing_fn(p, m.start())
            if cf is None: continue
            body = text[cf.body_start:m.start()]
            arm = None
            for mm in re.finditer(r'\bErr\s*\(\s*' + re.escape(m.group(1)) + r'\s*\)\s*=>', body): arm = mm
            if arm:
                subj = match_subject(body, arm.start())
                if subj:
                    for c in re.finditer(r'(?<![A-Za-z0-9_])([a-z_][a-z0-9_]*)\s*\(', subj):
                        if fns_by_name.get(c.group(1)): RECORD_FNS.add((p, c.group(1)))

    def record_sinks(p):
        text = files[p]['text']
        for (fp, name) in RECORD_FNS:
            if fp != p: continue
            for g in fns_by_file[p]:
                if g.name != name: continue
                body = text[g.body_start:g.end]
                for m in re.finditer(r'\bErr\s*\(', body):
                    e = find_matching(body, m.end()-1, '(', ')')
                    if e < 0: continue
                    inner = body[m.end():e].strip()
                    if body[e+1:e+4].lstrip().startswith('=>'): continue
                    yield ('dlq-record', inner, g.body_start + m.start())

    # ------------------------------------------------------------- funnel arms
    def funnel_findings():
        p = 'src/handlers/postgres_gate.rs'
        if p not in files: return
        text = files[p]['text']
        fn = [g for g in fns_by_file[p] if g.name == 'store_err_to_response']
        if not fn: return
        g = fn[0]; body = text[g.body_start:g.end]
        # variant text fields from the enum definition
        enum_fields = {}
        for q, d in files.items():
            mm = re.search(r'pub enum StoreError\s*\{', d['text'])
            if not mm: continue
            e = find_matching(d['text'], mm.end()-1, '{', '}')
            for vm in re.finditer(r'\n\s+([A-Z][A-Za-z0-9]*)\s*(\{[^}]*\}|\([^)]*\))?', d['text'][mm.end():e]):
                fields = []
                if vm.group(2) and vm.group(2).startswith('{'):
                    for part in split_args(vm.group(2)[1:-1]):
                        fm = re.match(r'\s*(?:pub\s+)?([a-z_]+)\s*:\s*(.+)', part.strip(), re.S)
                        if fm and re.search(r'String|str|Cow|PathBuf', fm.group(2)): fields.append(fm.group(1))
                enum_fields[vm.group(1)] = fields
        for am in re.finditer(r'StoreError::([A-Z][A-Za-z0-9]*)\s*(?:\{[^}]*\}|\([^)]*\))?\s*(?:\|\s*StoreError::([A-Z][A-Za-z0-9]*)\s*(?:\{[^}]*\}|\([^)]*\))?)*\s*=>\s*', body):
            arm_start = am.end()
            if body[arm_start:arm_start+1] == '{':
                be = find_matching(body, arm_start, '{', '}'); arm = body[arm_start:be+1]
            else:
                arm = expr_until(body, arm_start, stop_tokens=(',\n',))
            variants = [am.group(1)] + [v for v in re.findall(r'StoreError::([A-Z][A-Za-z0-9]*)', am.group(0))[1:]]
            # rendering shape: the RESPONSE text expression of the arm, judged like any other sink.
            # A pattern binding (`{ detail }`, `{ detail: d }`) maps to the variant's field; `e` maps to
            # every text field of the variant. An arm that renders through anything but a declared typed
            # mapper (redact_*, a bare field, a prefix wrapper) is judged by where the field's text came from.
            tuples = list(re.finditer(r'\(\s*StatusCode::[A-Z_]+\s*,\s*', arm))
            if not tuples: continue
            tm = tuples[-1]; te = find_matching(arm, tm.start(), '(', ')')
            resp_expr = arm[tm.end():te] if te > 0 else ''
            if classify_expr(resp_expr, 'value') is CLEAN: continue           # a constant / msg:: const / a typed mapper alone
            bound = {}                                                           # binding name -> field name
            for pm in re.finditer(r'\{([^}]*)\}', am.group(0)):
                for part in split_args(pm.group(1)):
                    part = part.strip()
                    if not part or part == '..': continue
                    mm = re.match(r'([a-z_][a-z0-9_]*)\s*(?::\s*([a-z_][a-z0-9_]*))?$', part)
                    if mm: bound[mm.group(2) or mm.group(1)] = mm.group(1)
            rendered = rendered_idents(resp_expr)
            spelled = 'e.to_string()' if 'e' in rendered else ', '.join(sorted(rendered)) or resp_expr.strip()[:40]
            for v in variants:
                tf = enum_fields.get(v, [])
                if not tf: continue
                fields = set(tf) if 'e' in rendered else {bound[n] for n in rendered if n in bound and bound[n] in tf}
                for fld in sorted(fields):
                    r = field_taint(v, fld, 0, [f'StoreError::{v}.{fld}'])
                    key = f'{p}:store_err_to_response:funnel-arm:StoreError::{v}.{fld}'
                    if r:
                        ledgered = disposition(key)
                        if ledgered:
                            add('INFO', key, p, line_of(text, g.body_start + arm_start), 'store_err_to_response', ledgered); continue
                        add('FAIL', key, p, line_of(text, g.body_start + arm_start), 'store_err_to_response',
                            f'funnel arm renders StoreError::{v} through `{resp_expr.strip()[:60]}` and its text field `{fld}` is FOREIGN: {r.why}. '
                            f'A masked value (redact_*) is still foreign — render an allowlisted projection or drop the detail from the body (operator log keeps it).')
                    else:
                        add('INFO', key, p, line_of(text, g.body_start + arm_start), 'store_err_to_response',
                            f'funnel arm renders StoreError::{v} unsanitised ({spelled}); text field `{fld}` walked to own-code constructions only (caller-safe by walk).')

    # ----------------------------------------------------------------- allowlist
    counts = collections.Counter()
    for _k, _v in DERIVED.items(): counts['derived:' + _k] = _v   # #3760 — the derived sink-function sets, surfaced
    counts['files_scanned'] = len(files)   # #3711 — surface the scan denominator so a file NOT in the tree (silently unscanned) cannot read as a pass
    allow = {}
    if ALLOWF and os.path.exists(ALLOWF):
        for l in open(ALLOWF):
            l = l.strip()
            if not l or l.startswith('#'): continue
            if '=' in l: k, v = l.split('=', 1); k, v = k.strip(), v.strip()
            else: k, v = l, ''
            # #3713 — `mapper=` is a SET, not a slot: the dict used to key every declaration on the
            # bare word `mapper`, so only the LAST `mapper=` line survived and the ones above it
            # were silently undeclared (a second funnel un-declared the first). Keyed per name.
            if k == 'mapper': k = f'mapper={v}'
            allow[k] = v
    EXTRA_MAPPERS = [v for k, v in allow.items() if k.startswith('mapper=')]

    def disposition(key):
        """The ledger's answer for a live foreign render: an INFO text for an `echo:` or `pending:#N`
        entry, None when the key is not ledgered. A masker-naming entry is NOT a disposition (the
        caller emits the FAIL). Shared by the sink walk and the funnel-arm walk so a funnel arm can
        be held under an issue exactly like any other sink (it could not be before)."""
        v = allow.get(key)
        if v is None: return None
        if v.startswith('echo:'):
            counts['ledger:echo'] += 1
            return f'acknowledged as ECHO direction (caller\'s own input): {v}'
        if re.match(r'pending:\s*#\d+', v):
            counts['ledger:pending'] += 1; counts['ledger:pending:' + v[8:].strip()] += 1
            return f'PENDING FIX under {v[8:].strip()} — still foreign, tracked, not yet closed'
        return None
    if EXTRA_MAPPERS:
        CLEAN_RE = re.compile(CLEAN_RE.pattern + '|' + '|'.join(re.escape(x) + r'\(' for x in EXTRA_MAPPERS))

    # -------------------------------------------------------------------- run
    for p in sorted(files):
        text = files[p]['text']
        for (kind, expr, at) in list(sink_exprs_in(p)) + list(record_sinks(p)):
            f = enclosing_fn(p, at)
            fname = f.name if f else '<module>'
            if kind == 'mcp-error' and f is None: continue
            counts['sinks'] += 1; counts['sink:' + kind] += 1
            r = taint_expr(expr, f, at, 0, [], 'value') if f else classify_expr(expr, 'value')
            if r is None: r = CLEAN
            if ONLY and p == ONLY: print(f'TRACE {p}:{line_of(text, at)} {kind} fn={fname} -> {r.kind or "clean"} {r.why} :: {expr.strip()[:100]!r}', file=sys.stderr)
            if not r:
                counts['clean'] += 1; continue
            ln = line_of(text, at)
            key = f'{p}:{fname}:{kind}:{r.kind}'
            ledgered = disposition(key)
            if ledgered:
                add('INFO', key, p, ln, fname, ledgered); continue
            # apply the rule to itself: an ack that names a masker is refused
            if key in allow and re.search(r'redact|mask|scrub', allow[key]):
                add('FAIL', key, p, ln, fname, f'allowlist entry `{allow[key]}` names a MASKER — masking is not a passing state; render from an allowlist or drop.'); continue
            add('FAIL', key, p, ln, fname, f'{kind}: FOREIGN ({r.kind}) text rendered to a caller — {r.why} — expr: {expr.strip()[:140]}')
    funnel_findings()
    live_keys = {x['key'] for x in findings}
    for k, v in allow.items():
        if k.startswith('mapper='): continue
        if k not in live_keys: add('NOTICE', k, '(allowlist)', 0, '-', f'ledger entry no longer matches a live site (fixed or moved): {k}={v}')


    order = {'CRITICAL': 0, 'FAIL': 1, 'WARN': 2, 'NOTICE': 3, 'INFO': 4}
    findings.sort(key=lambda x: (order[x['sev']], x['file'], x['line']))
    return findings, counts


# ------------------------------------------------------------------ self-test
def _write(root, rel, text):
    p = os.path.join(root, rel); os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'w') as fh: fh.write(text)

def build_fixture(root):
    """A miniature src/ tree carrying every TIER-1 shape from the 2026-09-13 sweep AND the
    controls that must stay green: the safe funnels, echo-direction validators, typed refusals,
    operator-audience CLI output — and the masker control (a redact_* wrapper must stay RED)."""
    _write(root, 'src/store/mod.rs', '''
pub enum StoreError {
    NotFound { id: String },
    BackendUnavailable { detail: String },
    Stopped { issued_by: String },
    SchemaAheadOfBinary { detail: String },
    SchemaStampInvalid { detail: String },
    SchemaVersionPoisoned { detail: String },
    SchemaHatchMismatch { detail: String },
}
pub type StoreResult<T> = Result<T, StoreError>;
impl From<crate::storage::schema_guard::SchemaAheadOfBinary> for StoreError {
    fn from(e: crate::storage::schema_guard::SchemaAheadOfBinary) -> Self {
        Self::SchemaAheadOfBinary { detail: e.detail }
    }
}
impl From<crate::storage::schema_guard::SchemaStampZeroed> for StoreError {
    fn from(e: crate::storage::schema_guard::SchemaStampZeroed) -> Self {
        Self::SchemaStampInvalid { detail: e.detail }
    }
}
impl From<crate::storage::schema_guard::SchemaPoisoned> for StoreError {
    fn from(e: crate::storage::schema_guard::SchemaPoisoned) -> Self {
        Self::SchemaVersionPoisoned { detail: e.detail }
    }
}
impl From<crate::storage::schema_guard::SchemaHatch> for StoreError {
    fn from(e: crate::storage::schema_guard::SchemaHatch) -> Self {
        Self::SchemaHatchMismatch { detail: e.detail }
    }
}
''')
    _write(root, 'src/storage/schema_guard.rs', '''
pub struct SchemaAheadOfBinary { pub detail: String }
fn render(observed: i64, target: &str) -> String {
    format!("database at {target} is at schema {observed}")
}
pub fn evaluate(observed: i64, target: &str) -> Result<(), SchemaAheadOfBinary> {
    let detail = render(observed, target);
    Err(SchemaAheadOfBinary { detail })
}
pub struct SchemaStampZeroed { pub detail: String }
pub struct SchemaPoisoned { pub detail: String }
pub struct SchemaHatch { pub detail: String }
pub fn evaluate_stamp(observed: i64, target: &str) -> Result<(), SchemaStampZeroed> {
    Err(SchemaStampZeroed { detail: render(observed, target) })
}
pub fn evaluate_poison(observed: i64, target: &str) -> Result<(), SchemaPoisoned> {
    Err(SchemaPoisoned { detail: render(observed, target) })
}
pub fn evaluate_hatch(observed: i64, target: &str) -> Result<(), SchemaHatch> {
    Err(SchemaHatch { detail: render(observed, target) })
}
''')
    _write(root, 'src/storage/connection.rs', '''
pub fn open(db_path: &std::path::Path) -> anyhow::Result<()> {
    let target = db_path.display().to_string();
    crate::storage::schema_guard::evaluate(99, &target)?;
    crate::storage::schema_guard::evaluate_stamp(0, &target)?;
    crate::storage::schema_guard::evaluate_poison(9999, &target)?;
    crate::storage::schema_guard::evaluate_hatch(98, &target)?;
    Ok(())
}
''')
    _write(root, 'src/storage/record_stop.rs', '''
pub struct StorageError { pub msg: String }
pub fn gate_storage_conn(conn: &rusqlite::Connection) -> Result<(), StorageError> {
    Err(StorageError { msg: "record plane stopped".into() })
}
pub fn issued_stop(args: &Args) -> StoreError {
    StoreError::Stopped { issued_by: args.agent_id.clone() }
}
''')
    _write(root, 'src/validate.rs', '''
use anyhow::{Result, bail};
pub fn validate_id(id: &str) -> Result<()> {
    if id.bytes().any(|b| b == b' ') { bail!("id must not contain whitespace: {id}"); }
    Ok(())
}
''')
    _write(root, 'src/handlers/postgres_gate.rs', '''
pub fn store_err_to_response(e: crate::store::StoreError) -> Response {
    let (status, msg) = match e {
        StoreError::NotFound { .. } => (StatusCode::NOT_FOUND, "not found".to_string()),
        StoreError::BackendUnavailable { .. } => {
            tracing::error!("store backend error: {e}");
            (StatusCode::SERVICE_UNAVAILABLE, "storage backend unavailable".to_string())
        }
        StoreError::Stopped { .. } => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()),
        StoreError::SchemaAheadOfBinary { .. } => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()),
        // THE CONDUCTOR'S CHECK — the schema-guard 503 "fixed" by masking. The label is the DSN
        // minus only its userinfo password; redact_url_password leaves host, user, db and every
        // query parameter in the body. Both spellings must stay RED.
        StoreError::SchemaStampInvalid { .. } => (StatusCode::SERVICE_UNAVAILABLE, crate::logging::redact_url_password(&e.to_string())),
        StoreError::SchemaVersionPoisoned { detail } => (StatusCode::SERVICE_UNAVAILABLE, crate::logging::redact_urls_in_message(&detail)),
        // a bare destructured field, no wrapper at all
        StoreError::SchemaHatchMismatch { detail } => (StatusCode::SERVICE_UNAVAILABLE, detail),
    };
    (status, Json(json!({"error": msg}))).into_response()
}
pub fn sanitize_store_err_message(raw: &str) -> String { "sanitised".to_string() }
''')
    _write(root, 'src/handlers/errors.rs', '''
pub(crate) fn handler_error_500(e: &dyn std::fmt::Display) -> Response {
    tracing::error!("handler error: {e}");
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal error"}))).into_response()
}
''')
    _write(root, 'src/handlers/coord.rs', '''
async fn signal_send(app: AppState, signal: Signal) -> Response {
    // T1 — StoreError rendered straight into a 500 body, via a local helper (the #3703 shape)
    let insert_res = app.store.signal_send(&ctx, &signal).await.map(|_| ()).map_err(|e| signal_insert_error(&e.to_string()));
    if let Err(resp) = insert_res { return resp; }
    // T1 — the same, inline, sqlite twin (rusqlite text through a lock.0 call)
    let lock = app.db.lock().await;
    let current = match crate::actions::get(&lock.0, id) {
        Ok(a) => a,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("action_get failed: {e}")}))).into_response();
        }
    };
    // CONTROL — the safe funnels: never a finding
    if let Err(e) = app.store.action_get(&ctx, id).await { return store_err_to_response(e); }
    if let Err(e) = app.store.action_get(&ctx, id).await { return crate::handlers::errors::handler_error_500(&e); }
    // CONTROL — echo direction: a validator speaks only about the caller's own input
    if let Err(e) = crate::validate::validate_id(&id) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))).into_response();
    }
    // CONTROL — a typed refusal of our own (Result<_, StorageError>), rendered verbatim
    if let Err(e) = crate::storage::record_stop::gate_storage_conn(&lock.0) {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": e.msg}))).into_response();
    }
    // CONTROL — a constant and a msg:: constant
    if bad { return (StatusCode::FORBIDDEN, Json(json!({"error": crate::errors::msg::FORBIDDEN}))).into_response(); }
    // MASKER CONTROL — wrapping the foreign text in a redact_* helper must NOT pass
    if let Err(e) = app.store.action_get(&ctx, id).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": crate::logging::redact_url_password(&e.to_string())}))).into_response();
    }
    // CONTROL — the same text through a DECLARED typed mapper passes
    if let Err(e) = app.store.action_get(&ctx, id).await {
        return (StatusCode::CONFLICT, Json(json!({"error": sanitize_store_err_message(&e.to_string())}))).into_response();
    }
    // FUNNEL-BESIDE-A-LEAK — the mapper clears only what it wraps; the bare {e} beside it stays RED
    if let Err(e) = app.store.action_get(&ctx, id).await {
        return (StatusCode::CONFLICT, Json(json!({"error": format!("{}: {e}", sanitize_store_err_message(&e.to_string()))}))).into_response();
    }
    // PREFIX-WRAPPER CONTROL — msg::network(e) is a text->text helper, not a mapper: RED
    if let Err(e) = app.store.action_get(&ctx, id).await {
        return (StatusCode::BAD_GATEWAY, Json(json!({"error": crate::errors::msg::network(e)}))).into_response();
    }
    // LOCAL-WRAPPER CONTROL — a helper of any name that renders its argument is transparent: RED
    if let Err(e) = app.store.action_get(&ctx, id).await {
        return (StatusCode::BAD_GATEWAY, Json(json!({"error": describe(&e)}))).into_response();
    }
    (StatusCode::OK, Json(json!({"ok": true}))).into_response()
}
fn describe(e: &StoreError) -> String {
    format!("{e}")
}
fn signal_insert_error(detail: &str) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("signal insert failed: {detail}")}))).into_response()
}
''')
    _write(root, 'src/errors.rs', '''
pub mod msg {
    pub fn network(e: impl std::fmt::Display) -> String { format!("network: {e}") }
    pub const FORBIDDEN: &str = "forbidden";
}
''' + '''
pub enum MemoryError { DatabaseError(String), ValidationFailed(String) }
impl From<rusqlite::Error> for MemoryError {
    // T1 (sqlite twin) — the driver's text becomes a caller-rendered variant
    fn from(e: rusqlite::Error) -> Self { Self::DatabaseError(e.to_string()) }
}
impl From<crate::validate::ValidationError> for MemoryError {
    // CONTROL — our own typed validation error
    fn from(e: crate::validate::ValidationError) -> Self { Self::ValidationFailed(e.to_string()) }
}
''')
    _write(root, 'src/logging.rs', '''
pub fn redact_url_password(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for part in s.split(' ') { out.push_str(part); }
    out
}
''')
    _write(root, 'src/mcp/tools/relay.rs', '''
fn forward_to_http(url: &str) -> Result<Value, String> {
    let client = reqwest::blocking::Client::builder().build().map_err(|e| format!("build client: {e}"))?;
    // T1 — reqwest error Display (URL-bearing) into an MCP tool error (#3698)
    let resp = client.post(url).send().map_err(|e| format!("POST {url}: {e}"))?;
    let status = resp.status();
    let text = resp.text().map_err(|e| format!("read body: {e}"))?;
    // T1 — the peer's raw body relayed to the MCP caller
    if !status.is_success() {
        return Err(format!("{url} returned {status}: {text}"));
    }
    // CONTROL — a serde ERROR carries line/col only (the raw body beside it is the finding)
    serde_json::from_str::<Value>(&text).map_err(|e| format!("parse body: {e}"))
}
fn handle_get(conn: &rusqlite::Connection, id: &str) -> Result<Value, String> {
    // CONTROL — validator error to the caller: echo direction
    crate::validate::validate_id(id).map_err(|e| e.to_string())?;
    // T1 (sqlite twin) — rusqlite/anyhow text straight into the tool error
    let mem = db::get(conn, id).map_err(|e| e.to_string())?;
    // CONTROL — a typed mapper that never renders its input verbatim
    let _ = db::get(conn, id).map_err(|e| map_to_wire(e))?;
    Ok(json!(mem))
}
fn map_to_wire(err: db::ReflectError) -> String {
    tracing::warn!(error = %err, "refused");
    match err { db::ReflectError::Validation(m) => m, _ => "REFLECTION_FAILED".into() }
}
fn forward_sanitised(url: &str) -> Result<Value, String> {
    // #3711 SANITISER — url_display::* reduces the URL to scheme/host/path: {target} is CLEAN.
    let target = crate::url_display::url_origin_and_path(url);
    let resp = reqwest::blocking::get(url).map_err(|e| crate::url_display::network_failure(&e))?;
    let status = resp.status();
    // #3711 ANTI-LAUNDERING — url_display sanitises the ERROR e in THIS map_err; it says NOTHING
    // about the OK value `text` (the peer body). The sanitiser must NOT clean `text` just because
    // it shares the binding expression (the exact fc0b9516a transport.rs shape).
    let text = resp.text().map_err(|e| format!("read body from {target}: {}", crate::url_display::network_failure(&e)))?;
    // MIXED SINK — the finding MUST key on the peer body {text} (http), NEVER on the sanitised {target} (dsn).
    if !status.is_success() {
        return Err(format!("forward: {target} returned {status}: {text}"));
    }
    Ok(json!({"ok": true}))
}
fn log_only_if_let(conn: &rusqlite::Connection, id: &str) -> Result<Value, String> {
    // #3713 — the exact consolidate.rs shape: an EARLIER `Err(e) =>` arm sends a db error through a
    // declared mapper (clean), then a LATER `if let Err(e) = <db call>` PATTERN re-binds the same
    // name and only logs it. The pre-fix gate read the second `Err(e)` as a re-raise EXPRESSION,
    // resolved the name to the first arm's foreign binding, and FAILED a site whose value never
    // reached a caller.
    let mem = match db::get(conn, id) {
        Ok(m) => m,
        Err(e) => return Err(map_to_wire(e)),
    };
    if let Err(e) = db::set_embedding(conn, id, &mem) {
        tracing::warn!(error = %e, "embedding store failed (operator log)");
    }
    Ok(json!({"ok": true}))
}
fn reraise_ident(conn: &rusqlite::Connection, id: &str) -> Result<Value, String> {
    // #3713 POSITIVE — a bare `Err(e)` EXPRESSION re-raising db text is still a sink.
    let e = db::get(conn, id).map_err(|e| e.to_string()).unwrap_err();
    Err(e)
}
fn only_sanitised(url: &str) -> Result<Value, String> {
    // SPARE — a sink rendering ONLY a url_display-rendered value is CLEAN.
    let target = crate::url_display::url_origin_and_path(url);
    Err(format!("forward refused for {target}"))
}
fn block_tail_laundered(url: &str) -> Result<Value, String> {
    // #3711 gate-7 finding (d3f0d9544 probe) — a BLOCK closure body whose TAIL interpolates the peer
    // body {text} after a statement carrying an OWN marker (`e.classify()`; equally a validate_* /
    // parse / decode call). The old whole-block judgement let the marker launder the tail: RED.
    let target = crate::url_display::url_origin_and_path(url);
    let resp = reqwest::blocking::get(url).map_err(|e| crate::url_display::network_failure(&e))?;
    let status = resp.status();
    let text = resp.text().map_err(|e| crate::url_display::network_failure(&e))?;
    serde_json::from_str::<Value>(&text).map_err(|e| {
        let (category, line, column) = (e.classify(), e.line(), e.column());
        format!(
            "parse body from {target}: {category:?} at line {line} column {column} (raw: {text})"
        )
    })
}
fn block_return_exit(url: &str) -> Result<Value, String> {
    // A block whose TAIL is clean but whose early `return` renders the peer body: RED. The
    // exits of a block are its tail AND every top-level `return`, not the tail alone.
    let resp = reqwest::blocking::get(url).map_err(|e| crate::url_display::network_failure(&e))?;
    let text = resp.text().map_err(|e| crate::url_display::network_failure(&e))?;
    serde_json::from_str::<Value>(&text).map_err(|e| {
        if text.len() > 4096 {
            return format!("peer body too long: {text}");
        }
        let _ = e.classify();
        String::from("parse failed")
    })
}
fn block_tail_bound_sanitiser(url: &str) -> Result<Value, String> {
    // CONTROL (the d3f0d9544 transport.rs shape) — a block whose tail renders a value BOUND from the
    // url_display sanitiser is CLEAN: the let inside the block is the binding site, and the boundary
    // holds through it. The own-code serde construction (classify/line/column, never {e}) is CLEAN too.
    let target = crate::url_display::url_origin_and_path(url);
    let resp = reqwest::blocking::get(url).map_err(|e| {
        let reason = crate::url_display::network_failure(&e);
        format!("POST {target}: {reason}")
    })?;
    let text = resp.text().map_err(|e| {
        let reason = crate::url_display::network_failure(&e);
        format!("read body from {target}: {reason}")
    })?;
    serde_json::from_str::<Value>(&text).map_err(|e| {
        let (category, line, column) = (e.classify(), e.line(), e.column());
        format!("parse body from {target}: {category:?} at line {line} column {column}")
    })
}

// T1 (#3760) — an Ok RESULT payload carrying a driver error under a non-error key: the tool
// "succeeds" while the caller reads sqlx text. Only a derived, key-agnostic result walk sees it.
fn status_payload(conn: &rusqlite::Connection) -> Result<Value, String> {
    let index_note = match db::fts_probe(conn) {
        Ok(()) => "ok".to_string(),
        Err(e) => format!("index degraded: {e}"),
    };
    Ok(json!({"status": "ok", "index_note": index_note}))
}
// T1 (#3767 / #3766) — the live checkpoint.rs:162 shape: a guard BLOCK STATEMENT precedes a call to
// a crate fn whose DECLARED return type is rusqlite::Result, and the site `.to_string()`s the error.
// The pre-#3767 receiver scan read the guard's `}` as a nested closer and swallowed the block into the
// receiver; the OWN marker inside it (a `validate_*` call — on the live tree `validate_metadata` in the
// guard before checkpoint.rs:162) laundered the whole chunk: `no such table: checkpoints` reached
// `memory_checkpoint_create`'s caller while the gate scanned clean.
fn checkpoint_after_guard(conn: &rusqlite::Connection, id: &str) -> Result<Value, String> {
    if !id.is_empty() {
        crate::validate::validate_id(id).map_err(|e| e.to_string())?;
    }
    crate::checkpoints::insert(conn, id).map_err(|e| e.to_string())?;
    Ok(json!({"id": id}))
}
// T1 (#3767 / #3766) — the live share.rs:225 shape: the same guard-block-then-call, through a STORAGE
// anyhow chain (`db::insert` -> `insert_inner` -> `conn.execute(..)?`) instead of a declared rusqlite::Result.
fn share_after_guard(conn: &rusqlite::Connection, id: &str) -> Result<Value, String> {
    if !id.is_empty() {
        crate::validate::validate_id(id).map_err(|e| e.to_string())?;
    }
    db::insert(conn, id).map_err(|e| e.to_string())?;
    Ok(json!({"shared": id}))
}
// CONTROL (#3767) — a BLOCK EXPRESSION as the receiver (`match .. { .. }.map_err(..)`, the live
// forget.rs:41 / lineage.rs:126 shape) must STAY RED: the `}` here is part of the receiver.
fn block_receiver(conn: &rusqlite::Connection, id: &str, owner: Option<&str>) -> Result<Value, String> {
    let rows = match owner {
        Some(_) => db::insert(conn, id),
        None => db::insert(conn, id),
    }
    .map_err(|e| e.to_string())?;
    Ok(json!({"rows": rows}))
}
// CONTROL (#3767) — a guard block followed by an OWN-vocabulary call (a validator) must stay CLEAN:
// the boundary fix narrows the receiver, it must not manufacture a finding.
fn own_after_guard(id: &str) -> Result<Value, String> {
    if !id.is_empty() {
        crate::validate::validate_id(id).map_err(|e| e.to_string())?;
    }
    crate::validate::validate_namespace(id).map_err(|e| e.to_string())?;
    Ok(json!({"id": id}))
}
''')
    # #3767 — a crate module whose fns DECLARE the driver's error type (the live `crate::checkpoints::insert`)
    _write(root, 'src/checkpoints/mod.rs', '''
pub fn insert(conn: &Connection, id: &str) -> rusqlite::Result<String> {
    conn.execute("INSERT INTO checkpoints (id) VALUES (?1)", params![id])?;
    Ok(id.to_string())
}
''')
    # #3767 — the storage root the `db::` alias names: an anyhow chain over a driver call (the live `db::insert`)
    _write(root, 'src/storage/mod.rs', '''
pub fn insert(conn: &Connection, id: &str) -> Result<String> {
    insert_inner(conn, id)
}
fn insert_inner(conn: &Connection, id: &str) -> Result<String> {
    conn.execute("INSERT INTO memories (id) VALUES (?1)", params![id])?;
    Ok(id.to_string())
}
''')
    _write(root, 'src/hooks/chain.rs', '''
async fn fire(executor: &Executor, event: Event) -> ChainResult {
    let fire_result = executor.fire(event).await;
    match fire_result {
        Ok(d) => ChainResult::Allow,
        Err(e) => {
            // T1 — the hook subprocess's text relayed to the denied caller (#3704)
            ChainResult::Deny { reason: format!("hook errored: {e}"), code: 503 }
        }
    }
}
fn presence_deny(event: &str) -> ChainResult {
    // CONTROL — a reason the daemon composed from its own config
    ChainResult::Deny { reason: format!("required event {event} has no enabled hook"), code: 503 }
}
''')
    _write(root, 'src/subscriptions.rs', '''
fn deliver(url: &str) -> Outcome {
    let mut last_error = String::new();
    match send(url) {
        Ok(()) => {}
        Err(e) => { last_error = e; }
    }
    Outcome { last_error }
}
fn send(url: &str) -> Result<(), String> {
    let resp = match client.post(url).send() { Ok(r) => r, Err(e) => return Err(crate::errors::msg::network(e)) };
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        // CONTROL — a status code is a scalar
        return Err(format!("http-{status}"));
    }
    let ack_body = resp.text().map_err(|e| format!("ack-read: {e}"))?;
    let ack: serde_json::Value = match serde_json::from_str(&ack_body) {
        Ok(v) => v,
        // CONTROL — serde error
        Err(e) => return Err(format!("ack-decode: {e}")),
    };
    let status_field = ack.get("status").and_then(|v| v.as_str()).unwrap_or("");
    if status_field != "ack" {
        // T1 — the RECEIVER's ack field persisted into subscription_dlq.last_error (row 14)
        return Err(format!("ack-status: {status_field}"));
    }
    Ok(())
}
''')
    # #3760 — the fixture is DERIVED like the tree: a router registers the HTTP handlers and a
    # dispatch table registers the MCP tools. A response-shaped fn nothing routes (`unrouted_leak`)
    # is dead code, not a sink — the control that proves the set is derived, not enumerated.
    _write(root, 'src/lib.rs', '''
pub fn build_router() -> axum::Router {
    axum::Router::new()
        .route(handlers::routes::SIGNALS, post(handlers::coord::signal_send))
        .route(handlers::routes::IMPORT, post(handlers::coord::import_bulk))
        .route(handlers::routes::DETAIL, get(handlers::coord::detail_key_render).delete(handlers::coord::detail_key_render))
        .route(handlers::routes::KEYS, get(handlers::coord::resolved_path_render))
        .layer(axum::middleware::from_fn_with_state(state, handlers::coord::gate_layer))
}
''')
    _write(root, 'src/mcp/mod.rs', '''
macro_rules! register_mcp_tool { ($name:expr, $f:path) => { ($name, $f as DispatchFn) }; }
pub static TOOL_DISPATCH_TABLE: &[(&str, DispatchFn)] = &[
    register_mcp_tool!(tool_names::MEMORY_FORWARD, dispatch_forward),
    register_mcp_tool!(tool_names::MEMORY_GET, dispatch_get),
    register_mcp_tool!(tool_names::MEMORY_SANITISED, dispatch_sanitised),
    register_mcp_tool!(tool_names::MEMORY_LOG_ONLY, dispatch_log_only),
    register_mcp_tool!(tool_names::MEMORY_RERAISE, dispatch_reraise),
    register_mcp_tool!(tool_names::MEMORY_ONLY_SANITISED, dispatch_only_sanitised),
    register_mcp_tool!(tool_names::MEMORY_BLOCK_TAIL, dispatch_block_tail),
    register_mcp_tool!(tool_names::MEMORY_BLOCK_RETURN, dispatch_block_return),
    register_mcp_tool!(tool_names::MEMORY_BLOCK_BOUND, dispatch_block_bound),
    register_mcp_tool!(tool_names::MEMORY_STATUS, dispatch_status),
    register_mcp_tool!(tool_names::MEMORY_CHECKPOINT_CREATE, dispatch_checkpoint_after_guard),
    register_mcp_tool!(tool_names::MEMORY_SHARE, dispatch_share_after_guard),
    register_mcp_tool!(tool_names::MEMORY_BLOCK_RECEIVER, dispatch_block_receiver),
    register_mcp_tool!(tool_names::MEMORY_OWN_AFTER_GUARD, dispatch_own_after_guard),
];
fn dispatch_forward(ctx: &ToolDispatchCtx<'_>) -> Result<Value, String> { tools::relay::forward_to_http(ctx.url) }
fn dispatch_get(ctx: &ToolDispatchCtx<'_>) -> Result<Value, String> { tools::relay::handle_get(ctx.conn, ctx.id) }
fn dispatch_sanitised(ctx: &ToolDispatchCtx<'_>) -> Result<Value, String> { tools::relay::forward_sanitised(ctx.url) }
fn dispatch_log_only(ctx: &ToolDispatchCtx<'_>) -> Result<Value, String> { tools::relay::log_only_if_let(ctx.conn, ctx.id) }
fn dispatch_reraise(ctx: &ToolDispatchCtx<'_>) -> Result<Value, String> { tools::relay::reraise_ident(ctx.conn, ctx.id) }
fn dispatch_only_sanitised(ctx: &ToolDispatchCtx<'_>) -> Result<Value, String> { tools::relay::only_sanitised(ctx.url) }
fn dispatch_block_tail(ctx: &ToolDispatchCtx<'_>) -> Result<Value, String> { tools::relay::block_tail_laundered(ctx.url) }
fn dispatch_block_return(ctx: &ToolDispatchCtx<'_>) -> Result<Value, String> { tools::relay::block_return_exit(ctx.url) }
fn dispatch_block_bound(ctx: &ToolDispatchCtx<'_>) -> Result<Value, String> { tools::relay::block_tail_bound_sanitiser(ctx.url) }
fn dispatch_status(ctx: &ToolDispatchCtx<'_>) -> Result<Value, String> { tools::relay::status_payload(ctx.conn) }
fn dispatch_checkpoint_after_guard(ctx: &ToolDispatchCtx<'_>) -> Result<Value, String> { tools::relay::checkpoint_after_guard(ctx.conn, ctx.id) }
fn dispatch_share_after_guard(ctx: &ToolDispatchCtx<'_>) -> Result<Value, String> { tools::relay::share_after_guard(ctx.conn, ctx.id) }
fn dispatch_block_receiver(ctx: &ToolDispatchCtx<'_>) -> Result<Value, String> { tools::relay::block_receiver(ctx.conn, ctx.id, None) }
fn dispatch_own_after_guard(ctx: &ToolDispatchCtx<'_>) -> Result<Value, String> { tools::relay::own_after_guard(ctx.id) }
''')
    _write(root, 'src/handlers/import.rs', '''
// #3760 — the import envelope: a Vec<String> assembled by push and rendered under a key that is
// NOT "error". The pre-#3760 gate keyed the HTTP sink on the literal `"error"` and read
// `Vec::new()` as clean, so this leak (the live admin.rs:1577 shape) was invisible to it.
async fn import_bulk(app: AppState, body: Body) -> Response {
    let mut errors: Vec<String> = Vec::new();
    let mut imported = 0usize;
    for mem in body.memories {
        match app.store.enforce_governance_action(&mem.namespace).await {
            Ok(()) => imported += 1,
            Err(e) => {
                // T1 — a StoreError Display pushed into the envelope's errors[] (#3760)
                errors.push(format!("{}: governance error: {e}", mem.id));
                continue;
            }
        }
    }
    (StatusCode::OK, Json(json!({"imported": imported, "errors": errors}))).into_response()
}
// CONTROL — a Vec of OUR OWN text under the same key is clean
async fn import_clean(app: AppState, body: Body) -> Response {
    let mut errors: Vec<String> = Vec::new();
    for mem in body.memories {
        if let Err(e) = crate::validate::validate_id(&mem.id) {
            errors.push(format!("{}: {e}", mem.id));
        }
    }
    (StatusCode::OK, Json(json!({"imported": 0, "errors": errors}))).into_response()
}
// T1 — foreign text under a non-"error" key ("detail"), in a routed handler (#3760)
async fn detail_key_render(app: AppState, id: String) -> Response {
    match app.store.get(&ctx, &id).await {
        Ok(m) => (StatusCode::OK, Json(json!({"id": m.id, "title": m.title}))).into_response(),
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"code": "NOT_FOUND", "detail": format!("{e}")}))).into_response(),
    }
}
// T1 — the #3713 std::fs shape: a RESOLVED operator path (std::fs::canonicalize) under a non-"error"
// key. The pre-#3760 gate read `canonicalize` as OUR normaliser (`\\bcanonical`) and the key was not
// `"error"`, so it was invisible twice over.
async fn resolved_path_render(app: AppState) -> Response {
    let key_dir = crate::identity::keypair::default_key_dir().unwrap_or_default();
    let resolved = std::fs::canonicalize(&key_dir).unwrap_or(key_dir);
    (StatusCode::OK, Json(json!({"status": "ok", "keys": resolved.display().to_string()}))).into_response()
}
// CONTROL (derivation) — the SAME leak in a response-shaped fn nothing routes and nothing reaches:
// dead code is not a sink. The pre-#3760 gate flagged it by path prefix; the derived gate must not.
async fn unrouted_leak(app: AppState) -> Response {
    if let Err(e) = app.store.get(&ctx, "x").await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response();
    }
    (StatusCode::OK, Json(json!({"ok": true}))).into_response()
}
// T1 — a middleware layer the router installs is a sink too (#3760)
async fn gate_layer(req: Request, next: Next) -> Response {
    if let Err(e) = app.store.get(&ctx, "gate").await {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": format!("gate: {e}")}))).into_response();
    }
    next.run(req).await
}
''')
    _write(root, 'src/cli/report.rs', '''
pub fn run(conn: &rusqlite::Connection) -> anyhow::Result<()> {
    // CONTROL — operator audience: CLI --json output is TIER 2, never a gate finding
    match db::stats(conn) {
        Ok(s) => println!("{}", json!({"stats": s})),
        Err(e) => println!("{}", json!({"error": e.to_string()})),
    }
    Ok(())
}
''')

def self_test(scratch):
    root = os.path.join(scratch, 'foreign-text-selftest')
    if os.path.isdir(root):
        import shutil; shutil.rmtree(root)
    build_fixture(root)
    findings, counts = analyze(root, ALLOWF='/dev/null')
    fails = {x['key'] for x in findings if x['sev'] == 'FAIL'}
    lines = {(x['file'], x['line']) for x in findings if x['sev'] == 'FAIL'}
    def has(file, sub):
        return any(k.startswith(file + ':') and sub in k for k in fails)
    ok = True
    def expect(cond, what):
        nonlocal ok
        print(('  ok   ' if cond else '  FAIL ') + what)
        ok = ok and cond
    # positives — the 2026-09-13 TIER-1 shapes
    expect(has('src/handlers/coord.rs', ':signal_insert_error:http-body:db'), 'StoreError text through a local helper into a 500 body (#3703)')
    expect(has('src/handlers/coord.rs', ':signal_send:http-body:db'), 'rusqlite/anyhow text inline into a body (sqlite twin)')
    expect(has('src/mcp/tools/relay.rs', ':forward_to_http:mcp-error:http'), 'reqwest error / peer body into an MCP tool error (#3698)')
    expect(has('src/mcp/tools/relay.rs', ':handle_get:mcp-error:db'), 'db::get error text into an MCP tool error')
    # #3711 — url_display is a SANITISER, not a transparent helper (the gate-7 twin of the gate-2 fix)
    expect(has('src/mcp/tools/relay.rs', ':forward_sanitised:mcp-error:http'), '#3711 mixed sink fires on the peer body {text} (http)')
    expect(not has('src/mcp/tools/relay.rs', ':forward_sanitised:mcp-error:dsn'), '#3711 the url_display-sanitised {target} is NOT flagged as dsn (taint stops at the sanitiser, does not walk to the arg)')
    expect(not has('src/mcp/tools/relay.rs', ':only_sanitised:'), '#3711 a sink rendering ONLY a url_display-rendered value is CLEAN')
    expect(has('src/mcp/tools/relay.rs', ':block_tail_laundered:mcp-error:http'), 'BLOCK-TAIL (d3f0d9544 probe): a closure block whose tail interpolates {text} after an OWN-marker statement (e.classify()) stays RED — the marker does not launder the tail')
    expect(has('src/mcp/tools/relay.rs', ':block_return_exit:mcp-error:http'), 'BLOCK-RETURN: a clean tail does not hide a top-level `return` that renders the peer body')
    expect(not has('src/mcp/tools/relay.rs', ':block_tail_bound_sanitiser:'), 'BLOCK CONTROL (the fixed transport.rs shape): a tail rendering a url_display-bound `reason`, or an own-code serde classify/line/column construction, is CLEAN')
    # R-203 — the FROZEN pre-fix gate must ACCEPT the laundered block tail (reproducing the defect the
    # d3f0d9544 probe found); a self-test that only proved the live gate rejects it would be tautological.
    prefix = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test', 'fixtures', 'foreign-text-prefix-3711.py')
    try:
        import subprocess
        out = subprocess.run([sys.executable, prefix, root, '--allowlist=/dev/null', '--json'], capture_output=True, text=True, timeout=600).stdout
        frozen_fails = {x['key'] for x in json.loads(out)['findings'] if x['sev'] == 'FAIL'}
        expect(not any(':block_tail_laundered:' in k for k in frozen_fails), 'R-203: the FROZEN pre-fix gate (test/fixtures/foreign-text-prefix-3711.py) ACCEPTS the laundered block tail — the defect reproduces')
        expect(any(':forward_sanitised:mcp-error:http' in k for k in frozen_fails), 'R-203 sanity: the frozen gate still rejects the single-line {text} sink, so its silence on the block is the defect, not a broken run')
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as ex:
        expect(False, f'R-203: frozen prefix gate could not be run ({ex})')
    expect(not has('src/mcp/tools/relay.rs', ':log_only_if_let:'), '#3713: `if let Err(e) = <db call>` is a PATTERN, not a re-raise — a log-only arm is CLEAN')
    expect(has('src/mcp/tools/relay.rs', ':reraise_ident:mcp-error:db'), '#3713 POSITIVE: a bare `Err(e)` expression re-raising db text is still RED')
    prefix_3713 = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test', 'fixtures', 'foreign-text-prefix-3713.py')
    try:
        import subprocess
        out = subprocess.run([sys.executable, prefix_3713, root, '--allowlist=/dev/null', '--json'], capture_output=True, text=True, timeout=600).stdout
        frozen_3713 = {x['key'] for x in json.loads(out)['findings'] if x['sev'] == 'FAIL'}
        expect(any(':log_only_if_let:' in k for k in frozen_3713), 'R-203: the FROZEN pre-#3713 gate (test/fixtures/foreign-text-prefix-3713.py) FLAGS the log-only pattern — the defect reproduces')
        expect(any(':reraise_ident:mcp-error:db' in k for k in frozen_3713), 'R-203 sanity: the frozen gate rejects the bare re-raise too, so its verdict on the pattern is the defect, not a broken run')
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as ex:
        expect(False, f'R-203 (#3713): frozen prefix gate could not be run ({ex})')
    # #3760 — the sink set is DERIVED (router + dispatch table + reachability), never enumerated by
    # JSON key or path prefix, and a pushed collection is produced by its pushes.
    expect(has('src/handlers/import.rs', ':import_bulk:http-body:db'), '#3760: a StoreError Display pushed into the import envelope\'s "errors": [..] array is RED (the live admin.rs:1577 shape)')
    expect(not has('src/handlers/import.rs', ':import_clean:'), '#3760 CONTROL: a pushed Vec of our own validator text under the same key is CLEAN')
    expect(has('src/handlers/import.rs', ':detail_key_render:http-body:db'), '#3760: foreign text under a non-"error" key ("detail") in a ROUTED handler is RED')
    expect(not has('src/handlers/import.rs', ':unrouted_leak:'), '#3760 DERIVATION CONTROL: the same leak in a response-shaped fn nothing routes or reaches is NOT a sink (dead code) — the set is derived, not a path prefix')
    expect(has('src/handlers/import.rs', ':resolved_path_render:http-body:path'), '#3760 / #3713: a std::fs::canonicalize-RESOLVED operator path under a non-"error" key in a routed handler is RED (the resolver is a path producer, not our normaliser)')
    expect(has('src/handlers/import.rs', ':gate_layer:http-body:db'), '#3760: a middleware layer the router installs (from_fn_with_state) is a derived sink')
    expect(has('src/mcp/tools/relay.rs', ':status_payload:mcp-result:db'), '#3760: a driver error carried in an Ok RESULT payload under a non-error key is RED (key-agnostic result walk)')
    expect(counts.get('derived:http_roots', 0) >= 3 and counts.get('derived:mcp_roots', 0) >= 10, f"#3760 CONTROL: the roots were DERIVED from the fixture router / dispatch table (http {counts.get('derived:http_roots', 0)}, mcp {counts.get('derived:mcp_roots', 0)})")
    prefix_3760 = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test', 'fixtures', 'foreign-text-prefix-3760.py')
    try:
        import subprocess
        out = subprocess.run([sys.executable, prefix_3760, root, '--allowlist=/dev/null', '--json'], capture_output=True, text=True, timeout=600).stdout
        frozen_3760 = {x['key'] for x in json.loads(out)['findings'] if x['sev'] == 'FAIL'}
        expect(not any(':import_bulk:' in k for k in frozen_3760), 'R-203: the FROZEN pre-#3760 gate (test/fixtures/foreign-text-prefix-3760.py) ACCEPTS the errors[] array — the defect reproduces')
        expect(not any(':detail_key_render:' in k for k in frozen_3760), 'R-203: the FROZEN gate ACCEPTS foreign text under a non-"error" key — the key-literal enumeration reproduces')
        expect(any(':unrouted_leak:' in k for k in frozen_3760), 'R-203: the FROZEN gate flags the UNROUTED fn by path prefix — the enumeration-by-path reproduces')
        expect(not any(':resolved_path_render:' in k for k in frozen_3760), 'R-203: the FROZEN gate ACCEPTS the std::fs-resolved path under a non-"error" key — the `canonical` own-marker + key-literal blindness reproduce')
        expect(any(':signal_insert_error:http-body:db' in k for k in frozen_3760), 'R-203 sanity: the frozen gate still rejects the #3703 shape, so its silence above is the defect, not a broken run')
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as ex:
        expect(False, f'R-203 (#3760): frozen prefix gate could not be run ({ex})')
    # #3767 — the receiver of a `.map_err` chain is bounded by statements: a preceding guard BLOCK is not
    # part of it, so the crate fn it precedes (declared rusqlite::Result / a storage anyhow chain) is judged.
    expect(has('src/mcp/tools/relay.rs', ':checkpoint_after_guard:mcp-error:db'), '#3767: a guard block, then `crate::checkpoints::insert(..)` (declared rusqlite::Result) `.to_string()`d is RED (the live checkpoint.rs:162 / #3766 shape)')
    expect(has('src/mcp/tools/relay.rs', ':share_after_guard:mcp-error:db'), '#3767: a guard block, then `db::insert(..)` (a storage anyhow chain over conn.execute) `.to_string()`d is RED (the live share.rs:225 shape)')
    expect(has('src/mcp/tools/relay.rs', ':block_receiver:mcp-error:db'), '#3767 CONTROL: a `match .. { .. }.map_err(..)` whose ARMS are db calls stays RED — the block IS the receiver')
    expect(not has('src/mcp/tools/relay.rs', ':own_after_guard:'), '#3767 CONTROL: a guard block followed by an OWN validator call stays CLEAN — the boundary narrows, it never manufactures')
    prefix_3767 = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test', 'fixtures', 'foreign-text-prefix-3767.py')
    try:
        import subprocess
        out = subprocess.run([sys.executable, prefix_3767, root, '--allowlist=/dev/null', '--json'], capture_output=True, text=True, timeout=600).stdout
        frozen_3767 = {x['key'] for x in json.loads(out)['findings'] if x['sev'] == 'FAIL'}
        expect(not any(':checkpoint_after_guard:' in k for k in frozen_3767), 'R-203: the FROZEN pre-#3767 gate (test/fixtures/foreign-text-prefix-3767.py) ACCEPTS the guard-then-rusqlite::Result call — the swallowed-block launder reproduces')
        expect(not any(':share_after_guard:' in k for k in frozen_3767), 'R-203: the FROZEN gate ACCEPTS the guard-then-storage-anyhow call — the same launder reproduces')
        expect(any(':block_receiver:mcp-error:db' in k for k in frozen_3767), 'R-203 sanity: the frozen gate still rejects the block-RECEIVER shape, so its silence above is the defect, not a broken run')
        expect(any(':handle_get:mcp-error:db' in k for k in frozen_3767), 'R-203 sanity: the frozen gate still rejects a bare db call `.to_string()`d, so the declared-rusqlite/anyhow classes were never the gap')
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as ex:
        expect(False, f'R-203 (#3767): frozen prefix gate could not be run ({ex})')
    expect(has('src/hooks/chain.rs', ':fire:deny-reason:proc'), 'hook subprocess text in Deny.reason (#3704)')
    expect(has('src/errors.rs', ':from:memory-error:db'), 'From<rusqlite::Error> -> MemoryError::DatabaseError(e.to_string())')
    expect(has('src/subscriptions.rs', ':send:dlq-record:http'), "receiver's ack field persisted into subscription_dlq.last_error")
    expect(has('src/handlers/postgres_gate.rs', 'funnel-arm:StoreError::SchemaAheadOfBinary.detail'), 'funnel arm renders a variant whose text field walks back to an operator path (schema-guard 503)')
    expect(has('src/handlers/postgres_gate.rs', 'funnel-arm:StoreError::SchemaStampInvalid.detail'), "CONDUCTOR'S CHECK: the schema-guard arm wrapped in redact_url_password(&e.to_string()) stays RED")
    expect(has('src/handlers/postgres_gate.rs', 'funnel-arm:StoreError::SchemaVersionPoisoned.detail'), "CONDUCTOR'S CHECK: { detail } => redact_urls_in_message(&detail) stays RED")
    expect(has('src/handlers/postgres_gate.rs', 'funnel-arm:StoreError::SchemaHatchMismatch.detail'), 'a bare destructured field rendered without any wrapper stays RED')
    # the self-check the Conductor asked for: masking must NOT be a passing state
    coord = [x for x in findings if x['file'] == 'src/handlers/coord.rs' and x['sev'] == 'FAIL']
    expect(any('redact_url_password' in x['text'] for x in coord), 'MASKER CONTROL: redact_url_password(&e.to_string()) stays RED')
    expect(any('sanitize_store_err_message(&e.to_string()))' in x['text'] and '{e}' in x['text'] for x in coord), 'FUNNEL-BESIDE-A-LEAK: a bare {e} next to a mapper call stays RED')
    expect(any('msg::network(e)' in x['text'] for x in coord), 'PREFIX-WRAPPER CONTROL: msg::network(e) stays RED')
    expect(any('describe(&e)' in x['text'] for x in coord), 'LOCAL-WRAPPER CONTROL: describe(&e) (renders its argument) stays RED')
    # negative controls — one finding here is worse than no gate
    expect(not any('store_err_to_response' in x['text'] or 'handler_error_500' in x['text'] for x in coord), 'CONTROL: the safe funnels are never flagged')
    expect(counts.get('sink:funnel', 0) >= 2, f"CONTROL: the funnels were SEEN ({counts.get('sink:funnel', 0)} sites) and passed")
    expect(not any('validate_id' in x['text'] for x in findings if x['sev'] == 'FAIL'), 'CONTROL: echo-direction validator (validate_id) passes')
    expect(not any('gate_storage_conn' in x['text'] or 'e.msg' in x['text'] for x in coord), 'CONTROL: a typed refusal of our own passes')
    expect(not any(x['text'].endswith('sanitize_store_err_message(&e.to_string())') for x in coord), 'CONTROL: a declared typed mapper passes')
    expect(not any('map_to_wire' in x['text'] for x in findings if x['sev'] == 'FAIL'), 'CONTROL: a mapper that never renders its input passes')
    expect(not has('src/hooks/chain.rs', ':presence_deny:'), 'CONTROL: a Deny.reason the daemon composed passes')
    expect(not has('src/errors.rs', ':from:memory-error:') or sum(1 for k in fails if k.startswith('src/errors.rs:')) == 1, 'CONTROL: From<ValidationError> passes (only the rusqlite From is flagged)')
    expect(not any(k.startswith('src/cli/') for k in fails), 'CONTROL: CLI --json output (operator audience) is never a finding')
    expect(not has('src/handlers/postgres_gate.rs', 'Stopped'), 'CONTROL: a funnel arm whose text field is our own (Stopped.issued_by) passes')
    expect(not any('http-{status}' in x['text'] or 'ack-decode' in x['text'] for x in findings if x['sev'] == 'FAIL'), 'CONTROL: a status code scalar and a serde error pass')
    # allowlist self-check: an entry that names a masker is refused
    allowf = os.path.join(root, 'allow.txt')
    key = next(k for k in fails if k.startswith('src/handlers/coord.rs:signal_send:http-body:db'))
    with open(allowf, 'w') as fh: fh.write(f'{key}=masked by redact_url_password\n')
    f2, _ = analyze(root, ALLOWF=allowf)
    expect(any(x['sev'] == 'FAIL' and 'names a MASKER' in x['text'] for x in f2), 'ALLOWLIST CONTROL: an entry that names a masker is itself a FAIL')
    with open(allowf, 'w') as fh: fh.write(f'{key}=echo: fixture ack\n')
    f3, _ = analyze(root, ALLOWF=allowf)
    expect(not any(x['key'] == key and x['sev'] == 'FAIL' for x in f3), 'ALLOWLIST CONTROL: an echo acknowledgement downgrades that key to INFO')
    # #3713 — TWO `mapper=` declarations must BOTH take effect (the second used to un-declare the first).
    with open(allowf, 'w') as fh: fh.write('mapper=map_to_wire\nmapper=second_mapper_never_called\n')
    f5, _ = analyze(root, ALLOWF=allowf)
    expect(not any('map_to_wire' in x['text'] for x in f5 if x['sev'] == 'FAIL'), 'MAPPER-SET CONTROL: the FIRST of two mapper= lines is still declared when a second follows it')
    # LEDGER LEGS (the #3688 ledger, three rules):
    #  (a) a `pending:#N` entry holds a live render as INFO, and the run reports it as LIVE, not silent;
    #  (b) a funnel-arm key is held by the ledger exactly like any other sink (it could not be before);
    #  (c) a stale entry is a NOTICE, never a pass; (d) keys are DETERMINISTIC across runs.
    fkey = next((k for k in fails if ':funnel-arm:' in k), None)
    expect(fkey is not None, 'LEDGER CONTROL: the fixture carries a funnel-arm finding to hold')
    with open(allowf, 'w') as fh:
        fh.write(f'{key}=pending:#1\n{fkey}=pending:#2\nsrc/gone.rs:gone:http-body:db=pending:#3\n')
    f4, c4 = analyze(root, ALLOWF=allowf)
    expect(not any(x['key'] in (key, fkey) and x['sev'] == 'FAIL' for x in f4), 'LEDGER CONTROL: a pending entry holds a live sink AND a live funnel arm as INFO')
    expect(c4['ledger:pending'] >= 2 and c4['ledger:pending:#1'] >= 1 and c4['ledger:pending:#2'] >= 1, 'LEDGER CONTROL: ledgered renders are counted LIVE per issue, never folded into clean')
    expect(any(x['sev'] == 'NOTICE' and 'src/gone.rs' in x['key'] for x in f4), 'LEDGER CONTROL: a stale entry is a NOTICE, not a pass')
    k1 = sorted(x['key'] for x in analyze(root, ALLOWF='/dev/null')[0]); k2 = sorted(x['key'] for x in analyze(root, ALLOWF='/dev/null')[0])
    expect(k1 == k2, 'LEDGER CONTROL: keys are deterministic across runs')
    print('foreign-text-to-caller self-test: ' + ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1

def main(argv):
    if '--self-test' in argv:
        scratch = os.path.join(os.getcwd(), '.local-runs')
        os.makedirs(scratch, exist_ok=True)
        return self_test(scratch)
    root = next((a for a in argv if not a.startswith('--')), '.')
    allowf = next((a.split('=', 1)[1] for a in argv if a.startswith('--allowlist=')), os.path.join(root, 'scripts/qc-allowlists/foreign-text-to-caller.txt'))
    verbose = '--verbose' in argv; json_out = '--json' in argv
    only = next((a.split('=', 1)[1] for a in argv if a.startswith('--only=')), None)
    findings, counts = analyze(root, allowf, verbose, only)
    # A scan root with no src/**.rs under it is a WRONG ROOT, not a clean tree: every ledger entry
    # would read as stale (NOTICE) and the summary would print "0 FAIL" over nothing. Refuse it,
    # loudly, before anything else is printed (the Conductor read exactly that run as a finding).
    if counts['files_scanned'] == 0:
        print(f"foreign-text-to-caller: REFUSED — scan root {root!r} has no src/**.rs files (wrong root? pass the repo root, not src/)", file=sys.stderr)
        return 2
    nfail = sum(1 for x in findings if x['sev'] == 'FAIL'); ninfo = sum(1 for x in findings if x['sev'] == 'INFO')
    if json_out:
        print(json.dumps({'findings': findings, 'counts': counts}, indent=1)); return 1 if nfail else 0
    for x in findings:
        if x['sev'] == 'INFO' and not verbose: continue
        print(f"  [{x['sev']}] {x['key']}\n         {x['file']}:{x['line']} in {x['fn']}: {x['text']}")
    by_src = collections.Counter(x['key'].rsplit(':', 1)[-1] for x in findings if x['sev'] == 'FAIL' and 'funnel-arm' not in x['key'])
    by_sink = collections.Counter(x['key'].split(':')[2] for x in findings if x['sev'] == 'FAIL')
    print(f"\nforeign-text-to-caller: {counts['files_scanned']} src/**.rs files scanned; sink fns DERIVED from the tree: "
          f"http {counts.get('derived:http_fns', 0)} (from {counts.get('derived:http_roots', 0)} routed handlers/middleware), "
          f"mcp {counts.get('derived:mcp_fns', 0)} (from {counts.get('derived:mcp_roots', 0)} dispatch entries); {counts['sinks']} caller-facing sinks examined "
          f"({', '.join(f'{k[5:]}={v}' for k, v in sorted(counts.items()) if k.startswith('sink:'))}); "
          f"{counts['clean']} clean; {nfail} FAIL; {ninfo} INFO")
    # Rule 3: LIVE foreign renders are reported SEPARATELY from what the ledger holds. A ledger that
    # turned findings into silence would be the same defect as a gate that certifies nothing.
    pending = counts['ledger:pending']; echo = counts['ledger:echo']
    live = nfail + pending
    walked = ninfo - pending - echo
    per_issue = ', '.join(f'{k.split(":", 2)[2]}={v}' for k, v in sorted(counts.items()) if k.startswith('ledger:pending:'))
    print(f"  LIVE foreign renders reaching a caller: {live} instances = {nfail} unledgered (FAIL) + {pending} ledgered pending"
          f"{' (' + per_issue + ')' if per_issue else ''}; {echo} acknowledged as caller echo; {walked} walked to own-code constructions.")
    if pending and not nfail:
        print('  The gate is green because every live render is TRACKED, not because none exists.')
    if nfail:
        print('  FAIL by source: ' + ', '.join(f'{k}={v}' for k, v in by_src.most_common()))
        print('  FAIL by sink:   ' + ', '.join(f'{k}={v}' for k, v in by_sink.most_common()))
        print('  Remedy: route the error through the typed funnel (store_err_to_response / handler_error_500 /')
        print('  a closed-vocabulary mapper) or drop the foreign detail from the caller-facing text and log it')
        print('  instead. Wrapping it in redact_*/mask_* does not pass. Echo-direction false positives are')
        print('  acknowledged as <key>=echo:<why> in scripts/qc-allowlists/foreign-text-to-caller.txt.')
    return 1 if nfail else 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
