**Cert gate instrument (#4333 R4 / #4434).** `scripts/check-bootstrap-cert-gate.sh`
LEG A now certifies BOTH binary shapes as separately named legs, because a
binary built without `sal-postgres` can no longer certify a postgres posture
(`dsn_floor_verdict` never returns `Pinned` there, fail-closed). **LEG A-pg**
(`sal,sal-postgres` binary, `AI_MEMORY_BIN_PG`) must exit 0 on the certified
config with its negative controls exiting 2; **LEG A-driverless** (binary
lacking `sal-postgres`, `AI_MEMORY_BIN`) must REFUSE with exit 2 and the
failing posture row must be `AI_MEMORY_PG_AT_REST_ATTESTED`. Both legs must
print `RUN`. Each binary is probed through its own parsed
`features --json` surface (#2676); a missing, unparseable or swapped probe is
exit 3 (INSTRUMENT ERROR), never a silent pass. A bare run self-builds the
`sal,sal-postgres` binary. New `--self-test` exercises every fail-closed path
with stub binaries. The `cert-postgres-age` workflow passes the pg build as
`AI_MEMORY_BIN_PG`.
