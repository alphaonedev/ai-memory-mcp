#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# Reference L4 host-adapter shim — calls `memory_capture_turn` via
# MCP stdio per RFC-0001 (`docs/rfc/RFC-0001-mcp-turn-capture.md`).
#
# This shim is the fallback path for hosts whose only integration
# surface is "spawn a process from a Stop / SessionEnd / per-turn
# hook." Hosts with native MCP integration call the tool directly
# without this shim.
#
# # Usage
#
#   capture-turn.sh \
#     --host-session-id "<opaque-session-id>" \
#     --host-turn-index <n> \
#     --role <user|assistant|tool_use|tool_result|system|other> \
#     --content-file <path-or-"-"-for-stdin> \
#     [--host-kind claude-code|codex|gemini|...] \
#     [--host-version <version>] \
#     [--namespace <ns>] \
#     [--timestamp-iso <RFC3339>] \
#     [--ai-memory-bin <path>]      # default: ai-memory in $PATH
#
# # Claude Code SessionStart / Stop hook example
#
# Add to `~/.claude/settings.json`:
#
#   {
#     "hooks": {
#       "Stop": [{
#         "matcher": "*",
#         "hooks": [{
#           "type": "command",
#           "command": "/path/to/capture-turn.sh \
#             --host-session-id \"$CLAUDE_SESSION_ID\" \
#             --host-turn-index \"$CLAUDE_TURN_INDEX\" \
#             --role assistant \
#             --content-file \"$CLAUDE_LAST_ASSISTANT_OUTPUT\" \
#             --host-kind claude-code"
#         }]
#       }]
#     }
#   }
#
# # Exit codes
#
# - 0  — the substrate PERSISTED the turn (the receipt carried a
#        non-empty `memory_id`; `dedup_hit:true` counts, the row exists)
# - 1  — usage error (missing required arg, bad value)
# - 2  — the turn was NOT persisted (transport fault, substrate error,
#        governance `ask`/`pending`, an unreadable receipt, or any
#        receipt this release cannot prove describes a stored row)
# - 3  — content file missing/unreadable
#
# #3544 — exit 0 used to mean "none of the failures I enumerated
# happened", so governance `ask` (nothing stored, no recovery handle),
# governance `pending` (queued, not stored) and an unreadable receipt all
# reported success for a turn the substrate never wrote. The verdict is
# now the PRESENCE of a persisted `memory_id`; everything else fails
# CLOSED. The exit-code SET is unchanged — only the meaning of 0 is,
# which is the defect. A `pending` turn is not lost: its `pending_id` is
# printed on stderr and redeems the turn via `memory_pending_approve`.
#
# Reading the receipt requires `jq`. Without jq this shim CANNOT prove
# the turn was persisted, so it refuses to report success (exit 2) rather
# than guess — degrade, never lie about durability.
#
# # Failure mode
#
# Per the architecture: this shim MUST NOT wedge the host's
# operation. On any non-persisted outcome, the shim emits a stderr WARN
# and exits 2. The host's Stop-hook integration should ignore the
# non-zero exit (it's a backstop, not a gate).

set -euo pipefail

HOST_SESSION_ID=""
HOST_TURN_INDEX=""
ROLE=""
CONTENT_FILE=""
HOST_KIND=""
HOST_VERSION=""
NAMESPACE=""
TIMESTAMP_ISO=""
AI_MEMORY_BIN="${AI_MEMORY_BIN:-ai-memory}"

usage() {
  # Print the header comment block: every line from the one after the shebang
  # up to the first non-comment line, with the leading "# " stripped. Derived
  # from the file, so editing the header can never desynchronise a line count
  # (it used to be a hardcoded `head -N`, which leaked body comments once the
  # header grew).
  awk 'NR == 1 { next } !/^#/ { exit } { sub(/^# ?/, ""); print }' "$0"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host-session-id) HOST_SESSION_ID="$2"; shift 2 ;;
    --host-turn-index) HOST_TURN_INDEX="$2"; shift 2 ;;
    --role)            ROLE="$2"; shift 2 ;;
    --content-file)    CONTENT_FILE="$2"; shift 2 ;;
    --host-kind)       HOST_KIND="$2"; shift 2 ;;
    --host-version)    HOST_VERSION="$2"; shift 2 ;;
    --namespace)       NAMESPACE="$2"; shift 2 ;;
    --timestamp-iso)   TIMESTAMP_ISO="$2"; shift 2 ;;
    --ai-memory-bin)   AI_MEMORY_BIN="$2"; shift 2 ;;
    -h|--help)         usage ;;
    *)                 echo "ERROR: unknown arg: $1" >&2; usage ;;
  esac
done

# Required-arg gate.
for var in HOST_SESSION_ID HOST_TURN_INDEX ROLE CONTENT_FILE; do
  if [[ -z "${!var}" ]]; then
    echo "ERROR: required arg --${var,,//_/-} missing" >&2
    usage
  fi
done

# Read content (file path or "-" for stdin).
if [[ "${CONTENT_FILE}" == "-" ]]; then
  CONTENT="$(cat)"
elif [[ -r "${CONTENT_FILE}" ]]; then
  CONTENT="$(cat "${CONTENT_FILE}")"
else
  echo "ERROR: content file not readable: ${CONTENT_FILE}" >&2
  exit 3
fi

# Build JSON request via jq for proper escaping. Falls back to a
# best-effort sed-escape if jq is unavailable (jq is the common
# case on dev hosts but may not be present in stripped CI images).
if command -v jq >/dev/null 2>&1; then
  REQUEST="$(jq -n \
    --arg sid "${HOST_SESSION_ID}" \
    --argjson tidx "${HOST_TURN_INDEX}" \
    --arg role "${ROLE}" \
    --arg content "${CONTENT}" \
    --arg host_kind "${HOST_KIND}" \
    --arg host_version "${HOST_VERSION}" \
    --arg namespace "${NAMESPACE}" \
    --arg ts "${TIMESTAMP_ISO}" \
    '{
       host_session_id: $sid,
       host_turn_index: $tidx,
       role: $role,
       content: $content
     }
     + (if $host_kind    != "" then {host_kind:    $host_kind   } else {} end)
     + (if $host_version != "" then {host_version: $host_version} else {} end)
     + (if $namespace    != "" then {namespace:    $namespace   } else {} end)
     + (if $ts           != "" then {timestamp_iso: $ts         } else {} end)')"
else
  # jq-less fallback — best-effort. Recommends operators install jq.
  echo "WARN: jq not found; using sed-escape fallback (content with quotes/backslashes may misparse)" >&2
  ESCAPED_CONTENT="$(printf '%s' "${CONTENT}" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g; s/$/\\n/' | tr -d '\n' | sed 's/\\n$//')"
  REQUEST='{"host_session_id":"'"${HOST_SESSION_ID}"'","host_turn_index":'"${HOST_TURN_INDEX}"',"role":"'"${ROLE}"'","content":"'"${ESCAPED_CONTENT}"'"'
  [[ -n "${HOST_KIND}"     ]] && REQUEST="${REQUEST},\"host_kind\":\"${HOST_KIND}\""
  [[ -n "${HOST_VERSION}"  ]] && REQUEST="${REQUEST},\"host_version\":\"${HOST_VERSION}\""
  [[ -n "${NAMESPACE}"     ]] && REQUEST="${REQUEST},\"namespace\":\"${NAMESPACE}\""
  [[ -n "${TIMESTAMP_ISO}" ]] && REQUEST="${REQUEST},\"timestamp_iso\":\"${TIMESTAMP_ISO}\""
  REQUEST="${REQUEST}}"
fi

# Wrap in the MCP JSON-RPC envelope.
# Per MCP spec: initialize handshake → tools/call → response → exit.
# A single round-trip is fine because the shim spawns one ai-memory
# subprocess per turn.
INIT_REQUEST='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"capture-turn-shim","version":"0.1"}}}'
INIT_NOTIFY='{"jsonrpc":"2.0","method":"notifications/initialized"}'
CALL_REQUEST="$(printf '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"memory_capture_turn","arguments":%s}}' "${REQUEST}")"

# Pipe both requests to the substrate. The substrate emits one
# response per request to stdout; we want the tools/call one.
RAW="$(printf '%s\n%s\n%s\n' "${INIT_REQUEST}" "${INIT_NOTIFY}" "${CALL_REQUEST}" \
  | "${AI_MEMORY_BIN}" mcp --profile full 2>&1)" || {
    echo "WARN: MCP call failed; substrate error follows:" >&2
    echo "${RAW}" >&2
    exit 2
  }

# Reading the receipt is a two-level JSON parse (`result.content[0].text` holds
# the tool payload as a JSON STRING - `src/mcp/mod.rs:3762`), which grep cannot
# do correctly. Without jq the shim cannot prove the turn was persisted, so it
# refuses to claim it was. Degrade, never lie about durability: the call has
# ALREADY been made at this point, so the turn may well be stored - what this
# shim refuses to do is REPORT a success it cannot verify.
if ! command -v jq >/dev/null 2>&1; then
  echo "${RAW}"
  echo "WARN: jq not found; the capture receipt cannot be parsed, so this shim CANNOT prove the turn was persisted - refusing to report success (install jq)" >&2
  exit 2
fi

# Select the tools/call response BY ITS ID, exactly as the sibling python/node
# adapters do. The previous `grep '^{"jsonrpc"' | tail -1` took the LAST
# JSON-looking line whatever it was, so an init frame - or any later
# notification - could be classified as the capture receipt. `-R` + `fromjson?`
# skips every line that is not JSON (the substrate's stderr is merged in above).
RESPONSE="$(printf '%s\n' "${RAW}" \
  | jq -R -c 'fromjson? | select((type == "object") and (.id == 2))' 2>/dev/null \
  | tail -1)" || RESPONSE=""
if [[ -z "${RESPONSE}" ]]; then
  echo "WARN: no capture response from substrate" >&2
  exit 2
fi

# Emit the receipt on the shim's stdout for the operator.
printf '%s\n' "${RESPONSE}" | jq . || printf '%s\n' "${RESPONSE}"

# ── #3544: the capture-outcome predicate ──────────────────────────────────
#
# The substrate is the source of truth for this vocabulary; measured at
# `src/mcp/tools/capture_turn.rs`:
#
#   :437-444  permission `Decision::Ask`     -> {"status": "ask", ...}
#             NOTHING is persisted; no id, no recovery handle.
#   :488-496  `GovernanceDecision::Pending`  -> {"status": "pending",
#             "pending_id", ...}  DURABLY QUEUED, redeemable.
#   :531-538  dedup hit   -> {"memory_id", "dedup_hit": true,  "layer": "L4", ...}
#   :539-547  fresh write -> {"memory_id", "dedup_hit": false, "layer": "L4", ...}
#
# `grep -n '"status"' src/mcp/tools/capture_turn.rs` returns exactly those two
# literals — that is the whole closed vocabulary. `Decision::Deny` /
# `GovernanceDecision::Deny` return `Err(..)`, which MCP renders as
# `isError: true` (`src/mcp/mod.rs`), never as a `status`. RFC-0001 pins
# `memory_id` in the result's `required` set
# (`docs/rfc/RFC-0001-mcp-turn-capture.md:160`).
#
# THE WHOLE PREDICATE: a turn is CAPTURED if and only if the tool payload
# carries a non-empty string `memory_id`. `status` is read only to say WHY and
# to carry the recovery handle — never to decide the verdict, so a status a
# later substrate release grows fails CLOSED without this program knowing it
# exists. Kept self-contained (one file, jq only) because operators copy this
# script to their host; the identical predicate is implemented by the sibling
# `python/capture_turn.py` and `node/capture-turn.mjs`, and all three are pinned
# to the same verdicts and the same stderr text by
# `clients/host-adapter-shim/tests/test_capture_outcome_conformance.py`.

CAPTURE_VERDICT_JQ='
def payload:
  if (.result | type) != "object" then null
  else
    (.result.content) as $c
    | if ($c | type) == "array" and ($c | length) > 0
         and (($c[0] | type) == "object")
         and (($c[0].text | type) == "string")
      then ($c[0].text | try fromjson catch null)
      else null
      end
  end;
def outcome:
  if type != "object" then
    {kind: "not_captured", detail: "capture response was not a JSON-RPC object"}
  elif (.error != null) then
    {kind: "not_captured", detail: "substrate returned JSON-RPC error"}
  elif ((.result | type) != "object") then
    {kind: "not_captured", detail: "capture response carried no result object"}
  elif (.result.isError == true) then
    {kind: "not_captured", detail: "substrate returned isError:true"}
  else
    payload as $p
    | if (($p | type) != "object") then
        {kind: "not_captured", detail: "capture result payload was unreadable (result.content[0].text is not a JSON object); refusing to count it as a captured turn"}
      elif ($p.status == "ask") then
        {kind: "ask", detail: "capture_turn returned status=ask (governance approval requested; NOTHING was persisted and there is no recovery handle); not counting as a captured turn"}
      elif ($p.status == "pending") then
        (if (($p.pending_id | type) == "string") and (($p.pending_id | length) > 0) then $p.pending_id else null end) as $pid
        | {kind: "pending", detail: ("capture_turn returned status=pending, pending_id=" + ($pid | tojson) + " (the turn is DURABLY QUEUED for approval, NOT lost; redeem it with memory_pending_approve); not counting as a captured turn")}
      elif ((($p.memory_id | type) == "string") and (($p.memory_id | length) > 0)) then
        {kind: "captured", detail: ""}
      else
        {kind: "not_captured", detail: ("capture_turn returned no memory_id (status=" + ($p.status | tojson) + "); the turn was NOT persisted - not counting as a captured turn")}
      end
  end;
outcome | .kind + "\t" + .detail
'

VERDICT="$(printf '%s' "${RESPONSE}" | jq -r "${CAPTURE_VERDICT_JQ}" 2>/dev/null)" || VERDICT=""
KIND="${VERDICT%%$'\t'*}"
DETAIL="${VERDICT#*$'\t'}"

if [[ -z "${VERDICT}" ]]; then
  echo "WARN: capture receipt was unreadable; the turn was NOT persisted - not counting as a captured turn" >&2
  exit 2
fi
if [[ "${KIND}" != "captured" ]]; then
  echo "WARN: ${DETAIL}" >&2
  exit 2
fi
exit 0
