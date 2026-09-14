#!/usr/bin/env bash
# check-url-sink-redaction.sh — #3688 gate 2.
#
# A URL-shaped value (url / uri / dsn / endpoint / peer_url / base_url) that is
# interpolated into a SINK — a tracing macro, eprintln!/println!, an anyhow!/
# bail! message, or a format! that becomes an error/context/note string — can
# carry credentials: a Postgres DSN password, a webhook or peer URL with
# basic-auth userinfo, an API base URL with a key in the query. Once it is in a
# log line or an error string it is in journald, in a forensic bundle, in a
# doctor report, in a DLQ row.
#
# Four instances reached review before this gate existed:
#   #3648 provider error text carried the request URL       (llm.rs)
#   #3649 tower-http's DefaultMakeSpan recorded the full URI (lib.rs)
#   #3667 sync-daemon logged the raw peer URL                (daemon_runtime.rs)
#   #3674 sqlx logged the DSN INSIDE THE DEPENDENCY          (store/postgres)
# The fourth is why redacting our own rendering is not enough: the value must
# be screened BEFORE it reaches anything that formats it.
#
# The redaction funnel is: crate::logging::redact_urls_in_message,
# crate::errors::without_request_url,
# LlmProvider::safe_name, or a binding that is itself the redacted alias
# (display_url / peer_log / redacted_*).
#
# NOT in the funnel, deliberately: crate::logging::redact_url_password.
# It masks ONLY the userinfo password (between the first ':' and the last '@')
# and returns every other shape UNCHANGED -- so a token in the path
# (https://hooks.slack.com/services/T/B/XXXX) or in the query (?token=SECRET)
# passes through it verbatim. Accepting it here would let a site go GREEN with
# the leak fully intact, which is the one thing a gate must never do.
# Redact by ALLOWLIST: render scheme/host/port and emit nothing else.
# See #3674, #3697, #3698.
#
# NOT flagged: URL CONSTRUCTION — `format!("{url}/api/tags")` builds a request
# target, it does not render one. The interpolation is followed by a path or
# query separator, and the result goes to an HTTP client, not a sink.
# NOT flagged: ALL_CAPS constants (MAX_SOURCE_URI_LEN is a length, not a URL).
set -u
cd "$(dirname "$0")/.." || exit 2
ALLOW=scripts/qc-allowlists/url-sink-redaction.txt
FAIL=0
SELF_TEST=0
[ "${1:-}" = "--self-test" ] && SELF_TEST=1

# Sink call sites: the line opens a message-rendering macro, or a format! whose
# statement is an error/context/note builder.
SINK_RE='(tracing::)?(trace|debug|info|warn|error)!\(|eprintln!\(|println!\(|anyhow!\(|bail!\(|(context|with_context|map_err|ok_or_else|note *= *Some|Err)\(.*format!\('
# A url-shaped BINDING inside a format placeholder. Lowercase snake only (no
# ALL_CAPS constants), with optional field path and :? / :# specs.
BIND_RE='\{[a-z0-9_.]*(url|uri|dsn|endpoint)[a-z0-9_.]*(:[^}]*)?\}'
# Redacted alias names and funnel calls that make a hit safe on the same window.
SAFE_RE='redact_urls_in_message|without_request_url|safe_name|\{display_url|\{peer_log|\{redacted|\{safe_url|screen_dsn|redact_dsn'


# #3711 — PROVENANCE recogniser for the crate::url_display allowlisted renderer.
# A value that ORIGINATES from crate::url_display::* (url_origin / url_origin_and_path
# / store_url_display / network_failure / TransportFailure) is scheme/host/port only
# and safe in any sink. We anchor on the MODULE PATH, not the local binding name:
# a name is a convention that drifts, and renaming the local `let url_display = ...`
# must not silently re-arm the gate. Given the flagged ident, resolve its nearest
# `let` binding in the enclosing fn and chase simple aliases (&x, x.as_str(),
# x.as_ref(), x.to_string(), x.clone(), x.to_owned(), bare x) up to 5 hops to a
# `url_display::` call. Also accept an inline `url_display::` call in the sink window.
# Exit 0 = safe (rendered by url_display), 1 = not proven safe.
url_display_provenance() { # file fnstart sinkline ident
  python3 - "$1" "$2" "$3" "$4" <<'PYE'
import sys, re
path, start, end, ident = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
lines = open(path, encoding="utf-8", errors="replace").read().split("\n")
# inline: a url_display:: render in the sink window (the sink line + its two
# continuation lines the template can span).
for l in lines[end-1:end+2]:
    if "url_display::" in l:
        sys.exit(0)
# collect single-line `let [mut] NAME[: T] = RHS;` bindings in the enclosing fn,
# from the fn header down to (and including) the sink line.
binding = {}
letre = re.compile(r"\blet\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]*)?=\s*(.+?);")
for l in lines[start-1:end]:
    m = letre.search(l)
    if m:
        binding[m.group(1)] = m.group(2).strip()
alias = re.compile(r"^&?\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\.as_str\(\)|\.as_ref\(\)|\.to_string\(\)|\.to_owned\(\)|\.clone\(\))?\s*$")
cur = ident
for _ in range(5):
    rhs = binding.get(cur)
    if rhs is None:
        sys.exit(1)                 # a fn param or unresolved local: not proven safe
    if "url_display::" in rhs:
        sys.exit(0)                 # provenance reaches the renderer module
    a = alias.match(rhs)
    if a:
        cur = a.group(1); continue  # one alias hop, keep chasing
    sys.exit(1)
sys.exit(1)
PYE
}


scan() { # $1 = root dir; prints "file:line  {binding}" per unredacted sink
  local root=$1; [ "$root" = "." ] && root=""
  grep -rnE "$SINK_RE" "${root:+$root/}src" --include=*.rs 2>/dev/null \
    | grep -vE '^[^:]+:[0-9]+:\s*//' \
    | while IFS= read -r hit; do
        file=${hit%%:*}; rest=${hit#*:}; line=${rest%%:*}; text=${rest#*:}
        # skip test modules: anything at/after `mod tests` in the file, and test paths
        case "$file" in */tests/*|*/tests.rs|*_test.rs|*_tests.rs) continue;; esac
        mt=$(grep -nE '^\s*(pub )?mod tests' "$file" | head -1 | cut -d: -f1)
        [ -n "$mt" ] && [ "$line" -ge "$mt" ] && continue
        # The template may sit on the sink line or on the next two continuation
        # lines (a multi-line format!/anyhow! call). Take the first binding found.
        tmpl=$(sed -n "${line},$((line+2))p" "$file")
        bind=$(printf '%s' "$tmpl" | grep -oE "$BIND_RE" | head -1)
        [ -z "$bind" ] && continue
        # URL construction: placeholder immediately followed by a path/query char
        printf '%s' "$tmpl" | grep -qE "$(printf '%s' "$bind" | sed 's/[][\.*^$?+(){}|\\]/\\&/g')[/?&]" && continue
        # redaction on the same statement (line + 2 lines of context)
        win=$(sed -n "$((line>2?line-2:1)),$((line+2))p" "$file")
        printf '%s' "$win" | grep -qE "$SAFE_RE" && continue
        # #3711 — spare a value rendered by crate::url_display (provenance, not name).
        fnline=$(sed -n "1,${line}p" "$file" | grep -nE '^[[:space:]]*(pub(\([a-z]+\))? )?(async )?fn ' | tail -1 | cut -d: -f1)
        ident=$(printf '%s' "$bind" | sed -E 's/^\{//; s/\}$//; s/:.*$//; s/\..*$//')
        url_display_provenance "$file" "${fnline:-1}" "$line" "$ident" && continue
        # Sink KIND: a log line (tracing / eprintln / println) versus an error or
        # note string. Echo-direction validators return `error` text to the very
        # caller that supplied the URL; a `log` line discloses it to everyone.
        kind=error; printf '%s' "$text" | grep -qE '(trace|debug|info|warn|error)!\(|eprintln!\(|println!\(' && kind=log
        # Enclosing fn: the nearest preceding `fn name(` — a stable key across line shifts.
        fnname=$(sed -n "1,${line}p" "$file" | grep -oE '^\s*(pub(\([a-z]+\))? )?(async )?fn [A-Za-z_][A-Za-z0-9_]*' | tail -1 | grep -oE '[A-Za-z_][A-Za-z0-9_]*$')
        echo "$file:$line  $file:${fnname:-?}:$kind:$bind"
      done
}

judge() { # $1 = allowlist path; reads "file:line  key" lines on stdin; sets LIVE/PENDING/NOTICE/FAIL
  local ALLOW=$1
  LIVE=0; PENDING=0; NOTICE=0
  # #3688/7-shape ledger for gate 2 (Conductor ruling on #3688): `<key>=pending:#NNNN` holds a REAL
  # disclosure-direction sink under a tracked issue. It prints as INFO (never folded into clean), is
  # counted LIVE per issue, and an entry that no longer matches any live site is a NOTICE (stale) —
  # so the issue's acceptance test is "the specific key stops matching", not a count dropping.
  # A bare key line is still the ECHO allowlist (a `log` sink is never allowlistable that way).
  SEEN_PENDING=$(mktemp "${TMPDIR:-.local-runs}/url-sink-seen.XXXXXX")
  PER_ISSUE=""
  while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    loc=${hit%%  *}; key=${hit##*  }
    LIVE=$((LIVE+1))
    [ -f "$ALLOW" ] && grep -qxF "$key" "$ALLOW" && continue
    if [ -f "$ALLOW" ] && issue=$(grep -E "^$(printf '%s' "$key" | sed 's/[][\.*^$?+(){}|]/\\&/g')=pending:#[0-9]+\s*$" "$ALLOW" | head -1 | sed -E 's/.*=pending:(#[0-9]+).*/\1/') && [ -n "$issue" ]; then
      echo "  [INFO] $loc  $key — PENDING FIX under $issue: still an unredacted sink, tracked, not yet closed"
      echo "$key" >> "$SEEN_PENDING"; PENDING=$((PENDING+1)); PER_ISSUE="$PER_ISSUE $issue"
      continue
    fi
    echo "  $loc  $key — URL reaches a sink unredacted; render via crate::url_display:: (scheme/host/port), or redact_urls_in_message for wrapped foreign errors"
    FAIL=$((FAIL+1))
  done
  # stale ledger entries: a pending key with no live site is fixed or moved — say so, never pass silently
  if [ -f "$ALLOW" ]; then
    while IFS= read -r lk; do
      [ -z "$lk" ] && continue
      grep -qxF "$lk" "$SEEN_PENDING" || { echo "  [NOTICE] $lk — ledger entry no longer matches a live site (fixed or moved): remove it"; NOTICE=$((NOTICE+1)); }
    done < <(grep -E '^[^#].*=pending:#[0-9]+\s*$' "$ALLOW" | sed -E 's/=pending:#[0-9]+\s*$//')
  fi
  rm -f "$SEEN_PENDING"
  [ "$PENDING" -gt 0 ] && echo "  LIVE unredacted sinks held by the ledger: $PENDING ($(printf '%s\n' $PER_ISSUE | sort | uniq -c | awk '{printf "%s=%s ", $2, $1}'| sed 's/ $//'))"
}

if [ "$SELF_TEST" -eq 1 ]; then
  # Negative control (#3667): the sync-daemon peer-URL log line as it stood
  # before the redaction landed. Plant it in a throwaway copy under the repo's
  # scratch, never /tmp, and require the gate to reject it.
  T=.local-runs/url-sink-selftest; rm -rf "$T"; mkdir -p "$T/src"
  cat > "$T/src/planted.rs" <<'RS'
fn cycle(peer_url: &str, e: &str) {
    tracing::warn!("sync-daemon: peer {peer_url} cycle failed: {e}");
}
fn build(url: &str) -> String { format!("{url}/api/v1/sync/push") }
fn ok(url: &str) { let peer_log = crate::logging::host_only(url); tracing::info!("peer={peer_log}"); }
fn rendered(url: &str) {
    let shown = crate::url_display::url_origin(url);
    let url_display = shown.as_str();
    tracing::warn!("SSRF guard rejected {url_display}");
}
fn aliased_leak(peer_url: &str) {
    let endpoint_url = peer_url;
    tracing::warn!("cannot reach {endpoint_url}");
}
RS
  got=$(scan "$T")
  rm -rf "$T"
  # MUST reject: line 2 (#3667 raw peer_url) and the aliased_leak (endpoint_url
  # chases only to a fn param, never to url_display). MUST spare: construction
  # (build), the redacted alias (ok), and the url_display-rendered value
  # (rendered) — the latter proving PROVENANCE across the 2-hop
  # `shown = url_display::url_origin(url); url_display = shown.as_str()` binding.
  # LEDGER LEGS (Conductor ruling on #3688): a `key=pending:#N` entry holds a live sink as INFO
  # (never FAIL, never folded into clean); a stale entry is a NOTICE, never a silent pass.
  T2=.local-runs/url-sink-selftest-ledger; rm -rf "$T2"; mkdir -p "$T2/src"
  cat > "$T2/src/planted.rs" <<'RS'
fn cycle(peer_url: &str, e: &str) {
    tracing::warn!("sync-daemon: peer {peer_url} cycle failed: {e}");
}
RS
  printf '%s\n' 'src/planted.rs:cycle:log:{peer_url}=pending:#1' 'src/gone.rs:x:log:{url}=pending:#2' > "$T2/allow.txt"
  LIVE=0; PENDING=0; NOTICE=0; FAIL=0
  ledger_out=$(judge "$T2/allow.txt" < <(scan "$T2" | sed "s#^$T2/##; s#  $T2/#  #"))
  rm -rf "$T2"
  ledger_ok=1
  printf '%s' "$ledger_out" | grep -qE '^\s*\[INFO\] src/planted.rs:2 .*PENDING FIX under #1' || ledger_ok=0
  printf '%s' "$ledger_out" | grep -qE '^\s*\[NOTICE\] src/gone.rs:x:log:\{url\}' || ledger_ok=0
  printf '%s' "$ledger_out" | grep -qE 'planted.rs:2 .*URL reaches a sink unredacted' && ledger_ok=0
  FAIL=0
  rej_3667=$(printf '%s' "$got" | grep -c 'planted.rs:2 ')
  rej_alias=$(printf '%s' "$got" | grep -cE 'planted.rs:1[0-9] .*\{endpoint_url\}')
  spared_ctor=$(printf '%s' "$got" | grep -cE 'planted.rs:5 ')
  spared_redact=$(printf '%s' "$got" | grep -cE 'planted.rs:6 ')
  spared_render=$(printf '%s' "$got" | grep -cE 'planted.rs:9 .*\{url_display\}')
  if [ "$rej_3667" -ge 1 ] && [ "$rej_alias" -ge 1 ] && [ "$spared_ctor" -eq 0 ] && [ "$spared_redact" -eq 0 ] && [ "$spared_render" -eq 0 ] && [ "$ledger_ok" -eq 1 ]; then
    echo "url-sink-redaction self-test: PASS (rejects the #3667 raw-URL shape AND an aliased non-url_display leak; spares construction, the redacted alias, and a crate::url_display-rendered value via provenance; a pending ledger entry holds a live sink as INFO and a stale entry is a NOTICE)"; exit 0
  fi
  echo "url-sink-redaction self-test: FAIL — got: $got"; echo "ledger legs (ok=$ledger_ok): $ledger_out"; exit 1
fi

LIVE=0; PENDING=0; NOTICE=0
judge "$ALLOW" < <(scan .)

if [ "$FAIL" -ne 0 ]; then
  cat <<MSG

url-sink-redaction gate (#3688/2): a URL-shaped value reaches a log/error sink unredacted
($FAIL failing of $LIVE sink interpolations found).

A url / dsn / endpoint / peer URL can carry credentials (DSN password, basic-auth
userinfo, API key in the query). In a tracing line, an anyhow!/bail! message or
a doctor note it lands in journald, forensic bundles and DLQ rows.

Fix: interpolate an ALLOWLIST-RENDERED form — scheme/host/port only. The
accepted renderer is crate::url_display::{url_origin, url_origin_and_path,
store_url_display, network_failure} (a value chased to a url_display:: call is
spared regardless of the local binding name), or crate::logging::host_only —
  let shown = crate::url_display::url_origin(&url);   // NEVER redact_url_password:
  // it masks only the userinfo password and passes a token in the path or
  // query through verbatim, so the gate would go green with the leak intact.
or drop the URL from the message (errors::without_request_url for reqwest errors).
If a site is ECHO-direction (the caller's own input refused back to that caller),
add its key \`<file>:<fn>:<log|error>:{binding}\` to
scripts/qc-allowlists/url-sink-redaction.txt WITH the reason. A \`log\` sink of a
config-sourced URL is never allowlistable.
MSG
  exit 1
fi
echo "url-sink-redaction: clean ($LIVE sink interpolations examined: $((LIVE-PENDING)) redacted or allowlisted, $PENDING ledgered pending, $NOTICE stale ledger entries)"
