# Evidence producers (#3547)

Tracked harnesses that produce published figures. A figure with no row in
`producer-map.json` is a defect. Every `producer.script` must appear in
`git ls-files`.

## Binding

Every bundle carries:

| field | computed from |
|---|---|
| `run_id` | unique per invocation |
| `daemon_binary_sha256` | SHA-256 of the process the harness addressed (`/proc/<pid>/exe` or the macOS `lsof` txt mapping) — never a typed hash |
| `addressed_exe_sha256` | same computation, stored twice so a mismatch is detectable |
| `source_commit` | `git rev-parse HEAD` of this repo |

`scripts/check-evidence-bundle.sh` refuses a bundle that is missing the
binding, a `PASS` with `oracle_kind=self-report`, a `mean_of_p99`
capacity method, or a prose verdict.

```
scripts/check-evidence-bundle.sh
scripts/check-evidence-bundle.sh --bundle path/to/record.json
scripts/check-evidence-bundle.sh --self-test
```

## Producers

See `producer-map.json`. Continuity and Big-10 used to live only on one
host under `.local-runs/` (gitignored). They now live here with
repo-relative paths. The unpublished dashboard "95 %" MCP-tools figure
had no producer; `mcp-tools-state.py` writes a state file only from a
named `--run-dir` capture and never invents a percentage.

Predicate rewrites (#3543): Big-10 plaintext requires a TLS-layer curl
exit in {35,52,56}; anonymous write requires 401/403 + error `code` +
zero delta; continuity readiness is a recall hit and retention compares
payload digest + version (clock 1 is `clock_1_harness_restart_to_health_ok_ms`);
stored `attest_level` mismatch is a non-zero exit; swarm `covered`
requires a persisted `memory_id` or a documented EXPECTED_REFUSAL, and
`pending` is its own bucket. Five negative fixtures under
`fixtures/neg-pred-*.json` are red under the legacy oracle and
green-as-FAIL under the new one (`python3 scripts/evidence/predicates.py
--self-test`).

## Writing a bundle

```
scripts/evidence/write-bundle.sh \
    --out .local-runs/bundle.json \
    --producer continuity-cycle \
    --pid "$DAEMON_PID" \
    --verdict PASS --oracle-kind independent
```
