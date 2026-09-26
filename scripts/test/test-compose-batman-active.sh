#!/usr/bin/env bash
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# #3838 — boot smoke for scripts/docker/docker-compose.batman-active.yml.
#
# The compose file shipped a stack that could not start, three times over:
# `serve --bind` (not a flag: clap usage error), `serve --tier` (not a flag),
# and then, with both fixed, `serve --host 0.0.0.0` with no API key, which the
# #1458 `api_key_bind_guard` refuses at BOOTSTRAP (exit 75). The first two are
# argv-parse failures. The third is not: argv parses and the daemon refuses at
# boot. So a `docker compose config` + argv check alone could never have caught
# it. This script runs what the stack runs, and waits until it is actually up:
#
#   1. `docker compose config` must REFUSE to render without AI_MEMORY_IMAGE or
#      without AI_MEMORY_API_KEY, naming the variable.
#   2. Render the stack with both set, and read the init-batman script, the
#      mcp argv + environment and the mcp healthcheck out of the RENDERED JSON
#      (after compose's `$$` unescaping, i.e. exactly what a container gets).
#   3. Run the rendered init-batman script on the host against a scratch
#      /data + /keys + a COPY of scripts/, with `ai-memory` = $AI_MEMORY_BIN.
#   4. Assert the config.toml it wrote is mode 0600 and carries the key.
#   5. Start the rendered mcp argv (`serve --host 0.0.0.0 ...`) on a free port
#      and run the RENDERED healthcheck (curl --cacert <key dir>/tls/local-ca.pem
#      https://localhost:<port>/api/v1/health) until it answers. The daemon
#      exiting first is a FAIL, reported with its output.
#
# Container paths are rewritten to scratch paths and 9077 to a free port. That
# is the only difference from the container, and it is what lets this run
# anywhere a release binary exists, with no image build.
#
# Usage: AI_MEMORY_BIN=target/release/ai-memory scripts/test/test-compose-batman-active.sh
# Scratch lives under .local-runs/ (project rule: never /tmp).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
COMPOSE="${ROOT}/scripts/docker/docker-compose.batman-active.yml"
BIN="${AI_MEMORY_BIN:-${ROOT}/target/release/ai-memory}"
BOOT_TIMEOUT_SECS="${BOOT_TIMEOUT_SECS:-60}"

fail() { echo "FAIL (#3838 compose smoke): $*" >&2; exit 1; }

command -v docker >/dev/null || fail "docker is required (docker compose config renders the stack)"
docker compose version >/dev/null 2>&1 || fail "the docker compose plugin is required"
command -v python3 >/dev/null || fail "python3 is required"
command -v curl >/dev/null || fail "curl is required (it is the stack's own healthcheck)"
[[ -x "${BIN}" ]] || fail "no ai-memory binary at ${BIN} (set AI_MEMORY_BIN)"
BIN="$(cd "$(dirname "${BIN}")" && pwd)/$(basename "${BIN}")"

T="${ROOT}/.local-runs/compose-smoke-3838-$$"
rm -rf "${T}"
mkdir -p "${T}/data" "${T}/keys" "${T}/bin" "${T}/home" "${T}/tmp"
DAEMON_PID=""
cleanup() {
    if [[ -n "${DAEMON_PID}" ]] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
        kill "${DAEMON_PID}" 2>/dev/null || true
        wait "${DAEMON_PID}" 2>/dev/null || true
    fi
    if [[ "${KEEP_SMOKE_DIR:-0}" != 1 ]]; then rm -rf "${T}"; fi
}
trap cleanup EXIT
chmod 700 "${T}/keys"
cp -R "${ROOT}/scripts" "${T}/opt-scripts"
ln -s "${BIN}" "${T}/bin/ai-memory"

# ---- 1. required variables refuse to render ---------------------------------
if AI_MEMORY_API_KEY=x docker compose -f "${COMPOSE}" config >/dev/null 2>"${T}/no-image.err"; then
    fail "compose rendered without AI_MEMORY_IMAGE; the stale default must stay removed"
fi
grep -q AI_MEMORY_IMAGE "${T}/no-image.err" || fail "missing-image refusal does not name AI_MEMORY_IMAGE: $(cat "${T}/no-image.err")"
if AI_MEMORY_IMAGE=smoke:local docker compose -f "${COMPOSE}" config >/dev/null 2>"${T}/no-key.err"; then
    fail "compose rendered without AI_MEMORY_API_KEY; serve would refuse its keyless 0.0.0.0 bind at boot"
fi
grep -q AI_MEMORY_API_KEY "${T}/no-key.err" || fail "missing-key refusal does not name AI_MEMORY_API_KEY: $(cat "${T}/no-key.err")"
echo "ok 1 - compose refuses to render without AI_MEMORY_IMAGE / AI_MEMORY_API_KEY"

# ---- 2. render ---------------------------------------------------------------
API_KEY="smoke3838$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
AI_MEMORY_IMAGE=smoke:local AI_MEMORY_API_KEY="${API_KEY}" \
    docker compose -f "${COMPOSE}" config --format json > "${T}/rendered.json"
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"

# Emit shell-safe, path-rewritten pieces of the rendered stack.
python3 - "${T}" "${PORT}" > "${T}/plan.sh" <<'PYEOF'
import json, shlex, sys
t, port = sys.argv[1], sys.argv[2]
r = json.load(open(f"{t}/rendered.json"))
svc = r["services"]
def rw(s):
    # `compose config` re-emits `$$` escapes (its output is itself a compose
    # file); the container runtime is what turns `$$` into `$`. Do the same.
    s = s.replace("$$", "$")
    return (s.replace("/opt/scripts", f"{t}/opt-scripts")
             .replace("/data/", f"{t}/data/").replace("/keys", f"{t}/keys")
             .replace("localhost:9077", f"localhost:{port}"))
def env_arr(name):
    env = svc[name].get("environment") or {}
    return " ".join(shlex.quote(f"{k}={rw(str(v))}") for k, v in env.items())
init = svc["init-batman"]
assert init["entrypoint"] == ["/bin/bash", "-c"], init["entrypoint"]
cmd = init["command"]
script = cmd[0] if isinstance(cmd, list) else cmd
open(f"{t}/init.sh", "w").write(rw(script))
mcp = svc["mcp"]
argv = [rw(a) for a in mcp["command"]]
i = argv.index("--port"); argv[i + 1] = port
hc = [rw(a) for a in mcp["healthcheck"]["test"]]
assert hc[0] == "CMD", hc
print("INIT_ENV=(" + env_arr("init-batman") + ")")
print("MCP_ENV=(" + env_arr("mcp") + ")")
print("MCP_ARGV=(" + " ".join(shlex.quote(a) for a in argv) + ")")
print("HEALTH_ARGV=(" + " ".join(shlex.quote(a) for a in hc[1:]) + ")")
PYEOF
# shellcheck disable=SC1091
source "${T}/plan.sh"
[[ " ${MCP_ARGV[*]} " == *" --host 0.0.0.0 "* ]] \
    || fail "the rendered mcp service no longer binds 0.0.0.0 (the published port needs it): ${MCP_ARGV[*]}"
echo "ok 2 - rendered: ${MCP_ARGV[*]}"

# A container starts with ONLY its image env + the rendered environment block.
# `env -i` reproduces that, so no host AI_MEMORY_* (e.g. AI_MEMORY_NO_CONFIG,
# which would hide the config.toml and its api_key) can make this pass or fail.
BASE_ENV=(PATH="${T}/bin:/usr/local/bin:/usr/bin:/bin" HOME="${T}/home" TMPDIR="${T}/tmp")

# ---- 3. run the rendered init-batman script ---------------------------------
env -i "${BASE_ENV[@]}" "${INIT_ENV[@]}" bash "${T}/init.sh" > "${T}/init.log" 2>&1 \
    || fail "rendered init-batman script failed:"$'\n'"$(tail -30 "${T}/init.log")"
grep -q 'init-batman complete' "${T}/init.log" || fail "init-batman did not complete: $(tail -10 "${T}/init.log")"
echo "ok 3 - rendered init-batman script completed"

# ---- 4. the config.toml is a secret -----------------------------------------
CFG="${T}/data/xdg/ai-memory/config.toml"
[[ -f "${CFG}" ]] || fail "init-batman wrote no ${CFG}"
MODE="$(stat -c '%a' "${CFG}" 2>/dev/null || stat -f '%Lp' "${CFG}")"
[[ "${MODE}" == 600 ]] || fail "config.toml holds the API key but is mode ${MODE}, not 600"
grep -q "^api_key = \"${API_KEY}\"$" "${CFG}" || fail "config.toml does not carry the AI_MEMORY_API_KEY"
grep -q '^tier = "autonomous"$' "${CFG}" || fail "config.toml lost the autonomous tier"
echo "ok 4 - config.toml is mode 600 and carries api_key + tier"

# ---- 5. the rendered serve argv boots and the rendered healthcheck answers --
env -i "${BASE_ENV[@]}" "${MCP_ENV[@]}" "${BIN}" "${MCP_ARGV[@]:1}" > "${T}/serve.log" 2>&1 &
DAEMON_PID=$!
deadline=$(( SECONDS + BOOT_TIMEOUT_SECS ))
healthy=0
while (( SECONDS < deadline )); do
    if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
        wait "${DAEMON_PID}" && rc=0 || rc=$?
        DAEMON_PID=""
        fail "the rendered serve command EXITED (rc=${rc}) before becoming healthy:"$'\n'"$(tail -20 "${T}/serve.log")"
    fi
    if "${HEALTH_ARGV[@]}" >/dev/null 2>&1; then healthy=1; break; fi
    sleep 1
done
(( healthy )) || fail "no healthy answer within ${BOOT_TIMEOUT_SECS}s from: ${HEALTH_ARGV[*]}"$'\n'"$(tail -20 "${T}/serve.log")"
echo "ok 5 - rendered serve argv is up and the rendered TLS healthcheck answers"
echo "PASS (#3838 compose smoke): the batman-active stack's init + serve boot as rendered"
