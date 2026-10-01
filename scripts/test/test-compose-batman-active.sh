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
#   5. Start the mcp service's EFFECTIVE argv (entrypoint + command, exactly
#      what the container runtime executes) on a free port and run the
#      RENDERED healthcheck (curl --cacert <key dir>/tls/local-ca.pem
#      https://localhost:<port>/api/v1/health) until it answers. The daemon
#      exiting first is a FAIL, reported with its output.
#   6. Start the curator's effective argv and require it still running after a
#      few seconds (an argv the CLI rejects exits 2 at once).
#   7. Run the sync service's effective argv with no SYNC_PEERS: it must reach
#      its documented idle exit 0 (the shell script parses and runs).
#   Plus the #3838 L8 secret-handling legs: 5b the key is enforced (none and a
#   wrong key 401, the right key 200); the key directories are 0700; 8 a key
#   outside the charset or shorter than 32 is refused (64) without touching
#   the file; 9 (#4213) a changed AI_MEMORY_API_KEY rotates the stored key
#   and, after the restart compose performs (depends_on restart: true), the old
#   key is refused and the new one accepted; 10 (#4291) with only a
#   table-scoped api_key present, init keeps it, restores the top-level key
#   and reports no rotation.
#
# Every service must declare its entrypoint EXPLICITLY (#3838, Codex review):
# the root Dockerfile sets ENTRYPOINT ["ai-memory"] and Dockerfile.batman-active
# sets none, so a command that relied on the image entrypoint ran
# `ai-memory ai-memory ...` under the image the compose usage line names.
#
# Container paths are rewritten to scratch paths and 9077 to a free port; argv
# is otherwise run exactly as rendered, with `ai-memory` resolving (via PATH) to
# the binary under test. LINUX ONLY: the stack runs in Linux containers, and on
# macOS the daemon's config resolution does not honour XDG_CONFIG_HOME, so a
# native macOS run would test a different config path than the container uses.
#
# Usage: AI_MEMORY_BIN=target/release/ai-memory scripts/test/test-compose-batman-active.sh
# Scratch lives under .local-runs/ (project rule: never /tmp).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
COMPOSE="${ROOT}/scripts/docker/docker-compose.batman-active.yml"
BIN="${AI_MEMORY_BIN:-${ROOT}/target/release/ai-memory}"
BOOT_TIMEOUT_SECS="${BOOT_TIMEOUT_SECS:-60}"

fail() { echo "FAIL (#3838 compose smoke): $*" >&2; exit 1; }

[[ "$(uname -s)" == Linux ]] || fail "Linux only: the stack runs in Linux containers, and macOS config resolution ignores XDG_CONFIG_HOME (see the header)"
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
CURATOR_PID=""
cleanup() {
    for pid in "${DAEMON_PID}" "${CURATOR_PID}"; do
        if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
            kill "${pid}" 2>/dev/null || true
            wait "${pid}" 2>/dev/null || true
        fi
    done
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
API_KEY="smoke3838$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
AI_MEMORY_IMAGE=smoke:local AI_MEMORY_API_KEY="${API_KEY}" SYNC_PEERS= \
    docker compose -f "${COMPOSE}" --profile sync config --format json > "${T}/rendered.json"
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
def effective(name):
    # What the container runtime executes: the service's entrypoint + command.
    # The entrypoint must be EXPLICIT, or the image's own ENTRYPOINT decides
    # (and differs between the two Dockerfiles this stack can run on).
    ep = svc[name].get("entrypoint")
    assert ep, f"{name}: no explicit entrypoint; the image ENTRYPOINT would prefix its command"
    cmd = svc[name].get("command") or []
    if isinstance(cmd, str):
        cmd = [cmd]
    return [rw(a) for a in list(ep) + list(cmd)]
def arr(name, argv):
    return f"{name}=(" + " ".join(shlex.quote(a) for a in argv) + ")"
init = effective("init-batman")
assert init[:2] == ["/bin/bash", "-c"], init[:2]
mcp = effective("mcp")
assert mcp[0] == "ai-memory" and mcp[1] != "ai-memory", mcp[:2]
i = mcp.index("--port"); mcp[i + 1] = port
cur = effective("curator")
assert cur[0] == "ai-memory" and cur[1] != "ai-memory", cur[:2]
syn = effective("sync")
assert syn[:2] == ["sh", "-c"], syn[:2]
for name in ("mcp", "curator", "sync"):
    dep = (svc[name].get("depends_on") or {}).get("init-batman") or {}
    # #4213: a re-run init (a rotated key) must restart the services.
    assert dep.get("restart") is True, f"{name}: depends_on init-batman lacks restart: true (#4213)"
hc = [rw(a) for a in svc["mcp"]["healthcheck"]["test"]]
assert hc[0] == "CMD", hc
for name, var in (("init-batman", "INIT_ENV"), ("mcp", "MCP_ENV"), ("curator", "CURATOR_ENV"), ("sync", "SYNC_ENV")):
    print(f"{var}=(" + env_arr(name) + ")")
print(arr("INIT_ARGV", init))
print(arr("MCP_ARGV", mcp))
print(arr("CURATOR_ARGV", cur))
print(arr("SYNC_ARGV", syn))
print(arr("HEALTH_ARGV", hc[1:]))
PYEOF
# shellcheck disable=SC1091
source "${T}/plan.sh"
[[ " ${MCP_ARGV[*]} " == *" --host 0.0.0.0 "* ]] \
    || fail "the rendered mcp service no longer binds 0.0.0.0 (the published port needs it): ${MCP_ARGV[*]}"
echo "ok 2 - rendered; every service declares its entrypoint and restarts on a re-run init; mcp runs: ${MCP_ARGV[*]}"

# A container starts with ONLY its image env + the rendered environment block.
# `env -i` reproduces that, so no host AI_MEMORY_* (e.g. AI_MEMORY_NO_CONFIG,
# which would hide the config.toml and its api_key) can make this pass or fail.
BASE_ENV=(PATH="${T}/bin:/usr/local/bin:/usr/bin:/bin" HOME="${T}/home" TMPDIR="${T}/tmp")

# ---- 3. run the rendered init-batman script ---------------------------------
env -i "${BASE_ENV[@]}" "${INIT_ENV[@]}" "${INIT_ARGV[@]}" > "${T}/init.log" 2>&1 \
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
for d in "${T}/data/xdg" "${T}/data/xdg/ai-memory"; do
    DMODE="$(stat -c '%a' "${d}" 2>/dev/null || stat -f '%Lp' "${d}")"
    [[ "${DMODE}" == 700 ]] || fail "${d} holds the key file but is mode ${DMODE}, not 700"
done
echo "ok 4 - config.toml is mode 600 in 0700 directories and carries api_key + tier"

# ---- 5. the rendered serve argv boots and the rendered healthcheck answers --
env -i "${BASE_ENV[@]}" "${MCP_ENV[@]}" "${MCP_ARGV[@]}" > "${T}/serve.log" 2>&1 &
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
echo "ok 5 - the mcp service's effective argv is up and the rendered TLS healthcheck answers"

# ---- 5b. the API key is enforced ---------------------------------------------
CA="${T}/keys/tls/local-ca.pem"
status_with() {  # status_with <key or empty>: HTTP status of an authenticated read
    local hdr=()
    [[ -n "$1" ]] && hdr=(-H "x-api-key: $1")
    curl -s -o /dev/null -w '%{http_code}' --cacert "${CA}" "${hdr[@]}" \
        "https://localhost:${PORT}/api/v1/memories?limit=1"
}
[[ "$(status_with '')" == 401 ]] || fail "no key was not refused with 401"
[[ "$(status_with "wrong${API_KEY}")" == 401 ]] || fail "a wrong key was not refused with 401"
[[ "$(status_with "${API_KEY}")" == 200 ]] || fail "the configured key was not accepted"
echo "ok 5b - the API key is enforced (none 401, wrong 401, right 200)"

# ---- 6. the curator's effective argv parses and keeps running ---------------
env -i "${BASE_ENV[@]}" "${CURATOR_ENV[@]}" "${CURATOR_ARGV[@]}" > "${T}/curator.log" 2>&1 &
CURATOR_PID=$!
sleep "${CURATOR_SETTLE_SECS:-6}"
if ! kill -0 "${CURATOR_PID}" 2>/dev/null; then
    wait "${CURATOR_PID}" && rc=0 || rc=$?
    CURATOR_PID=""
    fail "the curator service's effective argv EXITED (rc=${rc}):"$'\n'"$(tail -20 "${T}/curator.log")"
fi
echo "ok 6 - the curator service's effective argv is running"

# ---- 7. the sync service's script parses and idles without peers -------------
env -i "${BASE_ENV[@]}" "${SYNC_ENV[@]}" "${SYNC_ARGV[@]}" > "${T}/sync.log" 2>&1 \
    || fail "the sync service's effective argv failed with no SYNC_PEERS:"$'\n'"$(tail -10 "${T}/sync.log")"
grep -q 'sync daemon idle' "${T}/sync.log" || fail "the sync service did not reach its idle exit: $(tail -5 "${T}/sync.log")"
echo "ok 7 - the sync service's effective argv idles cleanly without peers"
# ---- 8. the key whitelist and minimum length refuse, without touching the file --
BEFORE="$(sha256sum "${CFG}")"
for bad in "bad\"quote$(printf 'x%.0s' {1..40})" 'short-key'; do
    if env -i "${BASE_ENV[@]}" "${INIT_ENV[@]}" AI_MEMORY_API_KEY="${bad}" "${INIT_ARGV[@]}" > "${T}/init-bad.log" 2>&1; then
        fail "init accepted an invalid AI_MEMORY_API_KEY (${#bad} chars)"
    else
        rc=$?
    fi
    [[ "${rc}" == 64 ]] || fail "init refused an invalid key with rc=${rc}, not 64: $(tail -3 "${T}/init-bad.log")"
done
[[ "$(sha256sum "${CFG}")" == "${BEFORE}" ]] || fail "a refused key changed config.toml"
echo "ok 8 - a key outside the charset, or shorter than 32, is refused (64) and config.toml is untouched"

# ---- 9. rotation (#4213): a new AI_MEMORY_API_KEY replaces the old one --------
NEW_KEY="rotated3838$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
env -i "${BASE_ENV[@]}" "${INIT_ENV[@]}" AI_MEMORY_API_KEY="${NEW_KEY}" "${INIT_ARGV[@]}" > "${T}/init-rot.log" 2>&1 \
    || fail "init failed on a rotated key: $(tail -10 "${T}/init-rot.log")"
grep -q 'API key rotated' "${T}/init-rot.log" || fail "init did not report the rotation: $(tail -5 "${T}/init-rot.log")"
[[ "$(grep -c '^api_key' "${CFG}")" == 1 ]] || fail "config.toml does not carry exactly one api_key after rotation"
grep -q "^api_key = \"${NEW_KEY}\"$" "${CFG}" || fail "config.toml does not carry the rotated key"
grep -q '^tier = "autonomous"$' "${CFG}" || fail "rotation lost the autonomous tier"
MODE="$(stat -c '%a' "${CFG}" 2>/dev/null || stat -f '%Lp' "${CFG}")"
[[ "${MODE}" == 600 ]] || fail "rotation left config.toml mode ${MODE}, not 600"
# Compose restarts the services after the re-run init (depends_on restart: true, asserted in ok 2).
kill "${DAEMON_PID}" 2>/dev/null || true
wait "${DAEMON_PID}" 2>/dev/null || true
env -i "${BASE_ENV[@]}" "${MCP_ENV[@]}" "${MCP_ARGV[@]}" > "${T}/serve2.log" 2>&1 &
DAEMON_PID=$!
deadline=$(( SECONDS + BOOT_TIMEOUT_SECS ))
until "${HEALTH_ARGV[@]}" >/dev/null 2>&1; do
    kill -0 "${DAEMON_PID}" 2>/dev/null || fail "serve exited after the rotation: $(tail -10 "${T}/serve2.log")"
    (( SECONDS < deadline )) || fail "serve not healthy after the rotation"
    sleep 1
done
[[ "$(status_with "${API_KEY}")" == 401 ]] || fail "the OLD key still works after rotation (#4213)"
[[ "$(status_with "${NEW_KEY}")" == 200 ]] || fail "the rotated key is not accepted"
echo "ok 9 - a changed AI_MEMORY_API_KEY rotates the key: old 401, new 200 (#4213)"

# ---- 10. only the TOP-LEVEL key is the init's to rewrite (#4291) --------------
# An api_key inside a table is operator config. The #4213 rewrite took the FIRST
# `^api_key =` line anywhere as "the stored key" and dropped every such line, so
# with only a table-scoped key present it deleted that key and reported a
# rotation that did not happen. Leave only a table-scoped key and re-run init:
# the table key must survive, the top-level key must come back, nothing rotated.
{ grep -v '^api_key[[:space:]]*=' "${CFG}"; printf '\n[llm]\napi_key = "table-scoped-keep-me"\n'; } > "${T}/cfg.edit"
cat "${T}/cfg.edit" > "${CFG}"
env -i "${BASE_ENV[@]}" "${INIT_ENV[@]}" AI_MEMORY_API_KEY="${NEW_KEY}" "${INIT_ARGV[@]}" > "${T}/init-table.log" 2>&1 \
    || fail "init failed with a table-scoped api_key present: $(tail -10 "${T}/init-table.log")"
grep -q 'API key rotated' "${T}/init-table.log" && fail "init reported a rotation that did not happen (#4291)"
grep -q '^api_key = "table-scoped-keep-me"$' "${CFG}" || fail "init dropped the table-scoped api_key (#4291)"
[[ "$(head -1 "${CFG}")" == "api_key = \"${NEW_KEY}\"" ]] || fail "init did not restore the top-level api_key first (#4291)"
[[ "$(grep -c '^api_key' "${CFG}")" == 2 ]] || fail "expected one top-level and one table-scoped api_key (#4291)"
echo "ok 10 - a table-scoped api_key survives init, the top-level key is restored, nothing is reported rotated (#4291)"
echo "PASS (#3838 compose smoke): the batman-active stack's services run as the container runtime runs them"
