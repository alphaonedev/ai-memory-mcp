#!/usr/bin/env bash
# Plan C / tier2-trackb config renderer (#3197).
#
# Sourced by entrypoint.plan-c.sh. Emits a TOML document with every
# interpolated value escaped as a TOML basic string, so a secret that
# contains `"`, `\`, or a trailing newline cannot produce invalid TOML
# that AppConfig::load_from fail-opens into a KEYLESS daemon.
#
# EX_CONFIG 78 on a key that still contains a control character after
# trailing-newline normalisation (an API key with a raw control char
# can never be presented in an HTTP header — admitting one would boot
# a permanently un-authenticatable daemon).
set -euo pipefail

# EX_CONFIG from sysexits.h — a config that cannot be honoured.
PLAN_C_EX_CONFIG=78

# stdin → stdout: TOML basic-string body (`\` → `\\`, `"` → `\"`,
# control chars → `\n`/`\t`/`\r`/`\uXXXX`). Python3 is in both runtime
# images (Dockerfile.plan-c, Dockerfile.tier2-trackb).
toml_escape_basic() {
  # chr() codes avoid nested-quote hell between bash single-quotes and
  # Python string literals. 92 = `\`, 34 = `"`.
  python3 -c '
import sys
out = []
bs = chr(92)
for ch in sys.stdin.read():
    o = ord(ch)
    if o == 92:
        out.append(bs * 2)
    elif o == 34:
        out.append(bs + ch)
    elif o == 10:
        out.append(bs + "n")
    elif o == 9:
        out.append(bs + "t")
    elif o == 13:
        out.append(bs + "r")
    elif o < 32:
        out.append(bs + ("u%04x" % o))
    else:
        out.append(ch)
sys.stdout.write("".join(out))
'
}

# Strip trailing newlines only (the docker-secret `$(cat f)` artifact).
# Refuse on any remaining control character or on a key that normalises
# to empty. Prints the normalised key to stdout; warns on stderr when
# a trailing newline was stripped.
plan_c_normalize_api_key() {
  # Read the key from the environment, NEVER argv: `python3 -c … "$KEY"`
  # would expose it in `/proc/<pid>/cmdline` (Fable #3243 item 3; same
  # non-argv channel as the #3217 capability probe). The shell already
  # holds `AI_MEMORY_API_KEY`; the child inherits it.
  python3 -c '
import os, sys
raw = os.environ.get("AI_MEMORY_API_KEY", "")
stripped = raw.rstrip("\n")
if stripped != raw:
    sys.stderr.write(
        "WARN: stripped trailing newline(s) from AI_MEMORY_API_KEY "
        "(docker-secret artefact)\n"
    )
if stripped == "":
    sys.stderr.write(
        "ERROR: AI_MEMORY_API_KEY normalises to empty; refusing to emit "
        "a keyless config (#3197)\n"
    )
    sys.exit(78)
for ch in stripped:
    if ord(ch) < 32:
        sys.stderr.write(
            "ERROR: AI_MEMORY_API_KEY contains a control character; "
            "refusing (#3197). An API key with a raw control char can "
            "never be presented in an HTTP header.\n"
        )
        sys.exit(78)
sys.stdout.write(stripped)
'
}

# Print the Plan C config.toml document to stdout. Reads TIER,
# OLLAMA_BASE_URL, LLM_MODEL, AUTO_TAG_MODEL, AI_MEMORY_API_KEY from
# the environment. Every interpolated value is TOML-basic-string escaped.
plan_c_render_config() {
  local tier ollama llm auto_tag api_key_line=""
  tier=$(printf '%s' "${TIER}" | toml_escape_basic)
  ollama=$(printf '%s' "${OLLAMA_BASE_URL}" | toml_escape_basic)
  llm=$(printf '%s' "${LLM_MODEL}" | toml_escape_basic)
  auto_tag=$(printf '%s' "${AUTO_TAG_MODEL}" | toml_escape_basic)
  if [ -n "${AI_MEMORY_API_KEY:-}" ]; then
    local normalised escaped
    normalised=$(plan_c_normalize_api_key) || return "${PLAN_C_EX_CONFIG}"
    escaped=$(printf '%s' "${normalised}" | toml_escape_basic)
    api_key_line="api_key = \"${escaped}\""
  fi
  cat <<TOML
tier = "${tier}"
ollama_url = "${ollama}"
embed_url = "${ollama}"
embedding_model = "nomic_embed_v15"
llm_model = "${llm}"
auto_tag_model = "${auto_tag}"
cross_encoder = true
${api_key_line}

[audit]
enabled = true
path = "/var/log/ai-memory/audit"
redact_content = true
hash_chain = true

[permissions]
mode = "enforce"
TOML
}
