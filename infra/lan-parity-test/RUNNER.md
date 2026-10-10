# LAN parity runner

Run `python3 infra/lan-parity-test/run-parity-tests.py` after preparing the existing
LAN PostgreSQL stack and exporting its CA to `.local-runs/lan-parity-ca.pem`.
`PG_CA` or `--ca` selects another CA. Both test passes require TLS `verify-full`.
Connection overrides are `--pg-host`, `--pg-port`, `--pg-user` and
`--maintenance-database`; provide a password only through `PGPASSWORD`.
Use `--cargo-wrapper <admission-wrapper.py>` where local Cargo admission is required.
The wrapper is invoked with the Python interpreter and `cargo` as its first argument.

Pass 1 runs the default release suite with `--test-threads=1` in a freshly created
database. Pass 2 builds/enumerates test binaries and gives each binary containing
ignored tests another fresh database, then runs `--include-ignored --test-threads=1`.
A failed Pass 1 does not prevent Pass 2. Enumeration/listing errors, failed test
execution, and cleanup errors produce a failing exit status. A binary with no
ignored tests contributes no additional Pass 2 coverage and is logged accordingly.

Database ownership begins only after successful CREATE. The runner cleans only
those exact names with ordinary DROP; it never sweeps a prefix or terminates server
sessions. An interrupted command receives a signal in its owned process group and
is drained before cleanup. A connected or otherwise undroppable database is reported
as failed cleanup and its name remains in the log; this is not a successful run.
Full logs are retained under `.local-runs/` using unique filenames. Connection
credentials are supplied to children through their environment, not command arguments.

The process-level regression corpus uses inert Cargo/PostgreSQL stand-ins and runs
with `python3 -I scripts/test/test_lan_parity_pass1_ephemeral_7031.py`. It does not
replace native PostgreSQL, AGE, pgvector or campaign acceptance evidence.
