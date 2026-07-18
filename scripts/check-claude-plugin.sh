#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# #1979 — structural validator for the Claude Code plugin marketplace manifest
# (.claude-plugin/marketplace.json + plugins/ai-memory/**). Runs at freeze / in
# CI so the shipped manifest is a VERIFIED artifact, not a claimed one.
#
# Checks (all HARD-BLOCK):
#   1. JSON well-formedness of every manifest file.
#   2. Required fields present (marketplace name/plugins; plugin name/version).
#   3. The plugin `source` path resolves to a dir with a plugin.json.
#   4. Every bundled hook / MCP `command` is `ai-memory` (the on-PATH binary the
#      plugin assumes) — no stray absolute paths or other binaries.
#   5. If the `claude` CLI is present: `claude plugin validate` passes.
#
# `--self-test` proves the gate is load-bearing (a corrupted copy must fail).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MARKETPLACE="$ROOT/.claude-plugin/marketplace.json"
PLUGIN_DIR="$ROOT/plugins/ai-memory"

fail() { echo "check-claude-plugin: FAIL — $*" >&2; exit 1; }

need_jq() { command -v jq >/dev/null 2>&1 || fail "jq is required"; }

validate_tree() {
  local mkt="$1" plugdir="$2"
  need_jq

  # 1. JSON well-formedness.
  jq empty "$mkt" 2>/dev/null || fail "marketplace.json is not valid JSON"
  local plugin_json="$plugdir/.claude-plugin/plugin.json"
  local mcp_json="$plugdir/.mcp.json"
  local hooks_json="$plugdir/hooks/hooks.json"
  [ -f "$plugin_json" ] || fail "missing plugin.json at $plugin_json"
  jq empty "$plugin_json" 2>/dev/null || fail "plugin.json is not valid JSON"
  jq empty "$mcp_json" 2>/dev/null || fail ".mcp.json is not valid JSON"
  jq empty "$hooks_json" 2>/dev/null || fail "hooks.json is not valid JSON"

  # 2. Required fields.
  [ "$(jq -r '.name // empty' "$mkt")" != "" ] || fail "marketplace.json: missing .name"
  [ "$(jq -r '.plugins | length' "$mkt")" -ge 1 ] || fail "marketplace.json: empty .plugins"
  [ "$(jq -r '.name // empty' "$plugin_json")" != "" ] || fail "plugin.json: missing .name"
  [ "$(jq -r '.version // empty' "$plugin_json")" != "" ] || fail "plugin.json: missing .version"

  # 3. The plugin source path resolves.
  local src
  src="$(jq -r '.plugins[0].source' "$mkt")"
  local resolved="$ROOT/${src#./}"
  [ -f "$resolved/.claude-plugin/plugin.json" ] \
    || fail "plugins[0].source '$src' does not resolve to a plugin.json"

  # 4. Every bundled command invokes the on-PATH `ai-memory` binary.
  local cmds
  cmds="$(jq -r '.mcpServers[].command' "$mcp_json"; \
          jq -r '.hooks[][].hooks[].command' "$hooks_json")"
  local c
  while IFS= read -r c; do
    [ -z "$c" ] && continue
    case "$c" in
      ai-memory|"ai-memory "*) : ;;
      *) fail "bundled command must invoke the on-PATH 'ai-memory' binary, got: '$c'" ;;
    esac
  done <<< "$cmds"

  # 5. Claude CLI structural validation, when available.
  if command -v claude >/dev/null 2>&1; then
    claude plugin validate "$mkt" >/dev/null 2>&1 \
      || fail "claude plugin validate rejected $mkt"
  else
    echo "check-claude-plugin: note — 'claude' CLI absent; skipped its validate pass"
  fi
}

if [ "${1:-}" = "--self-test" ]; then
  need_jq
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/.claude-plugin" "$tmp/plugins/ai-memory/.claude-plugin" \
           "$tmp/plugins/ai-memory/hooks"
  # A deliberately corrupt manifest: a bundled command that is NOT ai-memory.
  cp "$MARKETPLACE" "$tmp/.claude-plugin/marketplace.json"
  cp "$PLUGIN_DIR/.claude-plugin/plugin.json" "$tmp/plugins/ai-memory/.claude-plugin/plugin.json"
  echo '{"mcpServers":{"ai-memory":{"command":"/bin/sh","args":["-c","evil"]}}}' \
    > "$tmp/plugins/ai-memory/.mcp.json"
  cp "$PLUGIN_DIR/hooks/hooks.json" "$tmp/plugins/ai-memory/hooks/hooks.json"
  if ( ROOT="$tmp" MARKETPLACE="$tmp/.claude-plugin/marketplace.json" \
       validate_tree "$tmp/.claude-plugin/marketplace.json" "$tmp/plugins/ai-memory" ) 2>/dev/null; then
    echo "check-claude-plugin: SELF-TEST FAIL — gate accepted a non-ai-memory command" >&2
    exit 1
  fi
  echo "check-claude-plugin: self-test PASS (gate rejects a corrupted manifest)"
  exit 0
fi

validate_tree "$MARKETPLACE" "$PLUGIN_DIR"
echo "check-claude-plugin: PASS (.claude-plugin/ manifest structurally valid)"
