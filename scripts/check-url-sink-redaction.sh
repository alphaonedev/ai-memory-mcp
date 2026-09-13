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
        # Sink KIND: a log line (tracing / eprintln / println) versus an error or
        # note string. Echo-direction validators return `error` text to the very
        # caller that supplied the URL; a `log` line discloses it to everyone.
        kind=error; printf '%s' "$text" | grep -qE '(trace|debug|info|warn|error)!\(|eprintln!\(|println!\(' && kind=log
        # Enclosing fn: the nearest preceding `fn name(` — a stable key across line shifts.
        fnname=$(sed -n "1,${line}p" "$file" | grep -oE '^\s*(pub(\([a-z]+\))? )?(async )?fn [A-Za-z_][A-Za-z0-9_]*' | tail -1 | grep -oE '[A-Za-z_][A-Za-z0-9_]*$')
        echo "$file:$line  $file:${fnname:-?}:$kind:$bind"
      done
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
RS
  got=$(scan "$T")
  rm -rf "$T"
  if printf '%s' "$got" | grep -q 'planted.rs:2 ' && ! printf '%s' "$got" | grep -qE 'planted.rs:(4|5) '; then
    echo "url-sink-redaction self-test: PASS (rejects the #3667 shape, spares construction + redacted alias)"; exit 0
  fi
  echo "url-sink-redaction self-test: FAIL — got: $got"; exit 1
fi

LIVE=0
while IFS= read -r hit; do
  [ -z "$hit" ] && continue
  loc=${hit%%  *}; key=${hit##*  }
  LIVE=$((LIVE+1))
  [ -f "$ALLOW" ] && grep -qxF "$key" "$ALLOW" && continue
  echo "  $loc  $key — URL reaches a sink unredacted; render scheme/host/port only (allowlist), or redact_urls_in_message for wrapped foreign errors"
  FAIL=$((FAIL+1))
done < <(scan .)

if [ "$FAIL" -ne 0 ]; then
  cat <<MSG

url-sink-redaction gate (#3688/2): a URL-shaped value reaches a log/error sink unredacted
($FAIL failing of $LIVE sink interpolations found).

A url / dsn / endpoint / peer URL can carry credentials (DSN password, basic-auth
userinfo, API key in the query). In a tracing line, an anyhow!/bail! message or
a doctor note it lands in journald, forensic bundles and DLQ rows.

Fix: interpolate an ALLOWLIST-RENDERED form — scheme/host/port only —
  let shown = crate::logging::host_only(&url);   // NEVER redact_url_password:
  // it masks only the userinfo password and passes a token in the path or
  // query through verbatim, so the gate would go green with the leak intact.
or drop the URL from the message (errors::without_request_url for reqwest errors).
If a site is ECHO-direction (the caller's own input refused back to that caller),
add its key \`<file>:<fn>:<log|error>:{binding}\` to
scripts/qc-allowlists/url-sink-redaction.txt WITH the reason. A `log` sink of a
config-sourced URL is never allowlistable.
MSG
  exit 1
fi
echo "url-sink-redaction: clean ($LIVE sink interpolations, all redacted or allowlisted)"
