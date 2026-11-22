"""Impact-selected CI: index builder, selector and gate (umbrella #8240).

The package answers one question for a pull request: which CI jobs must run
for this diff. The answer is deterministic. An optional advisor may only ADD
job keys; nothing in this package can remove a selected job.

Modules:
    common       shared constants, glob matching, rules loading, schema
    build_index  builds the SQLite impact index (crates, deps, targets, rules)
    select       maps a git diff to job keys, crates and ordered test targets
    gate         aggregates `toJSON(needs)` into one pass/fail verdict

Scripts are run as files (`python3 -I scripts/ci/impact/select.py ...`) and
load their siblings by path through the one checked loader of #9399
(scripts/ci/sibling_load.py, embedded in each script). No script puts
`scripts/ci` on `sys.path` or imports this folder as a package by name; only
the unittest helper impact_fixture, which sits beside the tests, does, for
the tests.
"""
