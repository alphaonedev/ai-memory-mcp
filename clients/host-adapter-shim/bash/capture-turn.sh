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
# - 0  — success (either dedup_hit:true or memory created)
# - 1  — usage error (missing required arg, bad value)
# - 2  — MCP call failed (substrate error; check stderr)
# - 3  — content file missing/unreadable
#
# # Failure mode
#
# Per the architecture: this shim MUST NOT wedge the host's
# operation. On MCP failure, the shim emits a stderr WARN and
# exits 2. The host's Stop-hook integration should ignore the
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
  sed -n 's/^# \?//p' "$0" | head -64
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
# response per request to stdout; we capture the second (tools/call)
# and emit it on the shim's stdout for the operator.
RESPONSE="$(printf '%s\n%s\n%s\n' "${INIT_REQUEST}" "${INIT_NOTIFY}" "${CALL_REQUEST}" \
  | "${AI_MEMORY_BIN}" mcp --profile full 2>&1 | grep -E '^\{"jsonrpc"' | tail -1)" || {
    echo "WARN: MCP call failed; substrate error follows:" >&2
    echo "${RESPONSE}" >&2
    exit 2
  }

# Pretty-print the response if jq is available; otherwise emit raw.
if command -v jq >/dev/null 2>&1; then
  echo "${RESPONSE}" | jq .
else
  echo "${RESPONSE}"
fi

# Inspect for substrate-side error envelope (isError:true per MCP spec).
if echo "${RESPONSE}" | grep -q '"isError":true'; then
  echo "WARN: substrate returned isError:true; check the response envelope above" >&2
  exit 2
fi
