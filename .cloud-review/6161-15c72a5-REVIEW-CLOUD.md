# Cloud review PR #6171 head 15c72a590 (round 6): VERDICT REJECT

Lane `rev-6171-r6`, branch `cloud/f1/rev-6171-r6`, base `chain/promo6-ssh` =
`fa6b588e6b5dfa97370b4f073e60e66cb1ed1fa7`, subject head
`15c72a59029db180aa6922ef10f46399f2ce2a2c` (round-6 delta `4848491c2..15c72a590`:
`11dd79177` tests, `15c72a590` fix). Read-only review; no production code changed.

**Bottom line.** Every round-6 claim holds: R5-F1 (only known libpq keywords are
named), R5-F2/#6221 (percent-only decoding, `+` literal, kept segments re-emitted
raw), R5-F3 (later-segment extra `=`), R5-F4 (empty-host wording in all four
places). The tip tests go red on the 4848491c2 script exactly as claimed (10
failures, non-root) and green at tip on Python 3.11 and 3.13. Ten mutants of mine
were all caught. Across 24 driven failure paths and 50 000 fuzzed URLs the password
never reached stdout, stderr, an exception text, or psql's argv.

The verdict is REJECT because the exact rule this round ships ("the query is
percent-decoded only, as libpq does") is false for one byte class (F1: a
percent-encoded non-UTF-8 byte in the password becomes U+FFFD, a different
password), a documented-as-accepted socket-directory shape is rewritten into a
URL libpq rejects (F2), and the test meant to pin that acceptance cannot fail
(F3). All findings fail closed; none leaks a credential. A round 7 fixing F1-F5 is
about 25 script lines plus tests. f1 may reasonably downgrade to APPROVE-WITH-FIXES
if the parity surface is considered closed enough; the evidence below is what the
call rests on.

Oracle for every libpq statement here: `PQconninfoParse` called through ctypes on
the libpq bundled with `psycopg-binary 3.3.6` (`PQlibVersion() = 180006`, i.e.
libpq 18.6). psycopg's own `conninfo_to_dict` was not usable as the oracle because
it decodes values as UTF-8 and raises on the F1 byte class.

## Findings

Ranked by severity. "Fix size" counts script lines; tests extra.

### F1 (Medium) Non-UTF-8 percent-encoded bytes in the password are replaced by U+FFFD; libpq keeps the raw byte

- `scripts/ci/ensure-age-extension.py:158` (`password = unquote(raw_password)`) and
  `:179` (`password = unquote(raw_value)`). `urllib.parse.unquote` defaults to
  `errors="replace"`, so `%ff` or `%e9` (any byte that is not valid UTF-8 in
  context) decodes to `�`, which reaches `PGPASSWORD` as the three bytes
  `EF BF BD`. libpq's `conninfo_uri_decode` emits the single raw byte.
- Reproduced (lens 2): `postgres://u:Tr0ub%ff3@h/db` -> libpq password
  `b'Tr0ub\xff3'`, helper `PGPASSWORD` bytes `b'Tr0ub\xef\xbf\xbd3'`. Same for the
  query form. Fuzz (lens 7): 68 of 50 000 URLs, every one this cause.
- Effect: psql authenticates with a different password; the run ends with exit 1
  `age probe failed: psql exited 2` and no hint. No leak.
- libpq rule: `fe-connect.c` `conninfo_uri_decode` writes `(hi << 4) | lo` as one
  byte; only `%00` and malformed tokens are refused.
- Fix (2 lines + 1 test): `unquote(raw_password, errors="surrogateescape")` and
  `unquote(raw_value, errors="surrogateescape")`. Verified in-process:
  `os.fsencode(unquote("Tr0ub%ff3", errors="surrogateescape")) == b'Tr0ub\xff3'`,
  the sandbox's filesystem encoding is `utf-8`/`surrogateescape` (what `subprocess`
  uses for `env`), and the NUL refusal at `:192` still fires for `%00`. Test: fake
  psql records `os.fsencode(os.environ["PGPASSWORD"])` for `?password=a%ffb` and
  the userinfo form; assert `b"a\xffb"`.

### F2 (Low) A password-only userinfo with an empty host (`postgres://:pw@/db?host=%2F...`) is rewritten to `postgres:/db...`, which libpq rejects

- `scripts/ci/ensure-age-extension.py:160` sets `netloc = hostport` (= `""`) when
  the userinfo is only `:pw`; `:195` then calls `urlunsplit`, which drops the `//`
  for an empty netloc because `postgres` is not in `urllib.parse.uses_netloc`.
- Reproduced (lens 2): `postgres://:pw@/db?host=%2Ftmp` -> libpq accepts
  (`host=/tmp`, `password=pw`); helper target `postgres:/db?host=%2Ftmp`
  -> libpq `invalid connection option "postgres:/db?host"`. Fuzz: 21 of 50 000,
  every one this shape (B class).
- Contradicts the docstring (`:38-39`), `docs/DEV-CI-ENVIRONMENT.md:222-223` and
  the changelog, all of which say the `?host=%2F...` socket form is accepted; it is
  only accepted when a user name is present. Also inconsistent with `:142-144`,
  which refuses `postgres:///db` outright.
- Fix (1 line + 1 test): build the target by concatenation,
  `f"{parts.scheme}://{netloc}{parts.path}" + (f"?{query}" if query else "")`
  (verified: `postgres:///db?host=%2Ftmp` parses as `host=/tmp`), or refuse when
  `netloc` becomes empty with the same message as `:143`. Test:
  `mod.psql_target("postgres://:pw@/db?host=%2Ftmp") == ("postgres:///db?host=%2Ftmp", "pw")`.

### F3 (Low) `test_socket_directory_forms_with_a_host_part_are_accepted` cannot fail on a refusal

- `scripts/test/test_ensure_age_extension_6161.py:426-438`: the body is
  `try: mod.psql_target(url) except HelperError: assertNotIn("socket"/"empty host")`.
  A refusal with any other wording passes; acceptance is never asserted.
- Reproduced (lens 6, mutant M11): a script that refuses every socket-directory
  form with `tier URL file has no host; refused` -> `Ran 1 test ... OK`
  (`.local-runs/rev-6171-r6/lens6b-vacuity.txt`). This is why F2 was not caught.
- Fix (3 lines): assert `mod.psql_target(url) == (url, None)` for the two URLs and
  add the `:pw@` form from F2.

### F4 (Low) The rewrite turns libpq-invalid URLs into valid ones, so "refused when the two could disagree" and "kept segments are passed on exactly as written" overstate

- Three causes, all at `scripts/ci/ensure-age-extension.py`:
  1. Scheme case (`:137`, `:195`): `urlsplit` lower-cases the scheme and
     `urlunsplit` re-emits it, so `Postgres://u:pw@h/db` (libpq: `missing "="`,
     not a URI) becomes `postgres://u@h/db`. Fuzz: 1143 of 50 000.
  2. Invalid percent token or raw space in the password (`:158`, `:179`):
     `unquote` leaves `%zz`, a lone `%`, `%2` untouched and keeps a space; libpq
     refuses the whole URL (`invalid percent-encoded token`, `unexpected spaces
     found`). The helper sends `Tr0ub%zz3` / `Tr0ub 3` as the password. Fuzz: 226.
  3. Leading or inner empty query segment when a password is removed (`:171`,
     `:194`): `?&&password=x` and `?&password=x` are libpq errors (`missing
     key/value separator "=" ... ""`), the helper drops the empties and emits a
     clean URL. Fuzz: 12. (A trailing `&` is accepted by libpq and preserved; the
     passthrough branch keeps inner empties, which libpq then rejects at runtime.)
- No leak and the connection target is unchanged; psql simply connects where the
  later `psql "$new_url"` step in the same CI job will fail with libpq's own error,
  so the two halves of the step disagree about the same URL file.
- Fix (about 8 lines + 3 tests): refuse unless
  `url.startswith(("postgres://", "postgresql://"))`; refuse
  `re.search(r"%(?![0-9A-Fa-f]{2})", url)` and a raw space; refuse an empty
  segment anywhere but last (`any(not s for s in segments[:-1])` when
  `parts.query`). Each matches the docstring's stated policy of refusing where
  urllib and libpq disagree.

### F5 (Low) Fifteen libpq 18.6 keywords are refused with the "an unlisted query key" wording, and the `ssl=true` alias is refused

- Lens 5 diffed `ALLOWED_QUERY_KEYS` (`:79-85`) and `REFUSED_KNOWN_KEYS` (`:88-91`)
  against this libpq build's `PQconndefaults()` (50 keywords). In neither set:
  `fallback_application_name`, `sslnegotiation`, `sslcertmode`, `sslcrldir`,
  `sslcompression`, `ssl_min_protocol_version`, `ssl_max_protocol_version`,
  `min_protocol_version`, `max_protocol_version`, `gssdelegation`, `gsslib`,
  `replication`, `oauth_issuer`, `oauth_client_id`, `oauth_scope`. libpq marks
  none of them secret (`dispchar '*'` is only `password`, `sslpassword`,
  `oauth_client_secret`; `'D'` debug: `replication`, `scram_*`, `sslkeylogfile`).
- Reproduced (lens 4): `?sslnegotiation=direct` ->
  `tier URL file carries an unlisted query key, ...` (exit 2); `?ssl=true` (libpq
  JDBC alias for `sslmode=require`, accepted by the oracle) -> same message.
- Effect: a tier URL that legitimately carries `sslnegotiation=direct` or
  `sslcertmode=require` reds the macos-fed leg with a message that says the key is
  not a libpq parameter. `docs/DEV-CI-ENVIRONMENT.md:227-229` and the docstring
  `:42` describe the allowlist as "non-secret libpq parameters"; it is a subset.
- Fix (about 6 lines + 1 test): add the non-secret TLS/protocol/app-name keys
  (`fallback_application_name`, `sslnegotiation`, `sslcertmode`, `sslcrldir`,
  `sslcompression`, `ssl_min_protocol_version`, `ssl_max_protocol_version`,
  `min_protocol_version`, `max_protocol_version`) to `ALLOWED_QUERY_KEYS`; add the
  rest plus `ssl` to a third frozenset folded into `KNOWN_KEY_NAMES` so the message
  names them. Test: pin that the union covers the libpq 18 list.

### F6 (Low) A KeyboardInterrupt during the probe prints a traceback instead of one stderr line

- `scripts/ci/ensure-age-extension.py:395-401` catches `HelperError` only. Lens 3
  sent SIGINT while the fake psql slept: exit -2 and a 30-line traceback on stderr
  (source lines only; the password is absent). `changelog.d/6161.fixed.md:15-16`
  says "every failure is one `ensure-age-extension:` stderr line".
- Fix (3 lines): `except KeyboardInterrupt: print("ensure-age-extension:
  interrupted", file=sys.stderr); return 130`.

### F7 (Low) Two tests cannot pass as root

- `scripts/test/test_ensure_age_extension_6161.py:604-614` and `:616-629` inject
  the write error with `chmod(0o555)`, which uid 0 bypasses:
  `test_unwritable_lib_dir_fails_without_partial_state` and
  `test_share_failure_keeps_pinned_lib_file` fail with
  `AssertionError: 0 != 1` under root (lens 1, first run). CI runs the file in the
  hosted `classify` job on `ubuntu-latest` (`.github/workflows/ci.yml:223-224`) as
  the non-root `runner`, so CI is green; any root container (this sandbox, dev
  containers) sees `FAILED (failures=2)` on a correct script.
- Fix (4 lines): inject the failure uid-independently, e.g. replace the
  destination directory by a regular file so `mkdir(parents=True, exist_ok=True)`
  raises `FileExistsError` (still an `OSError`, same production path).

### F8 (Info) Path- and name-valued keys stay on psql's argv

- `ALLOWED_QUERY_KEYS` passes `sslkey`, `sslcert`, `sslrootcert`, `sslcrl`,
  `passfile`, `service`, `krbsrvname`, `requirepeer` through to argv. Their values
  are file paths or names, libpq classifies none as secret, and each has a `PG*`
  environment variable (lens 5). Listed because the lane's lens 5 names them;
  nothing credential-bearing is exposed. Fix if wanted (1 docstring line at `:41`):
  state that path/name keys are passed on argv by design.

## Evidence

1. **Red-on-base / green-on-tip.** Worktree at `4848491c2` with the tip test file
   copied in, run as the created non-root user `rev6171`:
   `python3 -m unittest scripts/test/test_ensure_age_extension_6161.py` ->
   `Ran 52 tests in 5.480s` / `FAILED (failures=10)`. Failing names:
   `test_empty_host_part_gets_a_clear_refusal`,
   `test_kept_query_segments_are_not_re_encoded`,
   `test_password_key_case_variants_are_rejected` (x2 subtests),
   `test_plus_in_query_password_is_literal` (x2),
   `test_plus_in_query_password_reaches_pgpassword_unchanged`,
   `test_unknown_query_key_is_rejected_without_its_value`,
   `test_unlisted_key_that_is_a_password_tail_is_not_echoed` (x2). Tip:
   `python3 -m unittest -v scripts/test/test_ensure_age_extension_6161.py` ->
   `Ran 52 tests in 5.846s` / `OK` (3.13.16); `python3.11 -m unittest ...` -> `OK`.
   As root both runs show `FAILED (failures=12)`: the 10 above plus the F7 pair,
   which also fail on the tip script as root.
2. **libpq parity** (`lens2.txt`, 58 shapes; table below). Parity for every
   `%2B`/`+`/`%20`/`%25`/`%3D`/`%26` form in both password positions, for
   `options` kept segments, `password` twice (query wins, last wins), IPv6,
   multi-host, `host=` override, both schemes, `%2F` socket host, `%40`/`%3A` in
   userinfo, `pass%77ord`. Divergences: F1 (`%ff`, `%e9`), F2 (`:pw@` empty host),
   F4 (`%zz`, `%`, `%2`, raw space, `Postgres://`, `?&&`, `?&`). Helper-stricter
   (fail closed, libpq would accept): `#`, `postgres:///db`, `ssl=true`.
3. **Secret leakage** (`lens3.txt`): 24 scenarios with password `Tr0ub4dor&3`
   (userinfo `%26`-encoded and raw): healthy, unreachable host and bad port with
   a psql that echoes argv+password on its stderr, EACCES, ENOENT, SIGTERM
   (`psql exited -15`), 60 s timeout (`TimeoutExpired`), SIGINT, psql stdout
   carrying the password, probe 0 + missing source, probe 0 + restore + still 0,
   pg_config missing, query form, raw `&` tail, bare segment, `?`/`#`/double `@`,
   keyword DSN, url-file is a directory, two-line file, `%00`, unknown argparse
   flag, in-process NUL argv (`ValueError`). `TOTAL LEAKS: 0 of 24`; psql argv
   never held the marker. Only SIGINT escapes the one-line contract (F6).
4. **Refusal construction** (`lens4.txt`): `PASSWORD`/`Password` -> `query key
   password (keys are case-sensitive)`; `pass%77ord` -> accepted and moved to env
   (libpq parity); `password%00`, 10 KiB key, `sslmode ` (trailing space),
   ` sslmode`, `not_a_key`, `a%26b`, empty key, `ssl`, `sslnegotiation` ->
   `an unlisted query key`; `SSLMODE` -> `query key sslmode (keys are
   case-sensitive)`; Kelvin-sign `Keepalives` -> `query key keepalives`
   (allowlist literal, not the input bytes); `oauth_client_secret`,
   `require_auth`, `sslpassword`, `SslPassword` -> named from the literal sets.
   No value echoed in any case; no non-literal key bytes echoed.
5. **Allowlist completeness** (`lens5.txt`): oracle `PQconndefaults()` = 50
   keywords. `ALLOWED_QUERY_KEYS - libpq = []`, `REFUSED_KNOWN_KEYS - libpq = []`,
   `secret(dispchar '*') & ALLOWED = []`; 15 libpq keys in neither set (F5);
   path/name keys on argv (F8).
6. **Mutation** (`lens6.txt`, run as `rev6171`): M1 `unquote_plus` -> caught
   (`test_plus_in_query_password_is_literal`, `..._reaches_pgpassword_unchanged`);
   M2 first-segment-only `=` check -> `test_query_segment_with_second_equals_is_rejected`;
   M3 echo raw key -> `test_unknown_query_key_is_rejected_without_its_value`,
   `test_unlisted_key_that_is_a_password_tail_is_not_echoed`; M4 drop empty-host
   refusal -> `test_empty_host_part_gets_a_clear_refusal`; M5 trailing `&` ->
   `test_kept_query_segments_are_not_re_encoded`; M6 decode kept segments -> same;
   M7 drop NUL refusal -> `test_percent_encoded_nul_in_password_is_rejected`;
   M8 case-insensitive `password` -> `test_password_key_case_variants_are_rejected`;
   M9 echo original casing -> same; M10 rebuild without password removal ->
   `test_query_without_password_is_passed_through_as_written`. 10/10 caught.
   M11 (refuse socket-directory forms) survives (F3).
7. **Fuzz** (`lens7.txt`): `python3 lens7_fuzz.py <script> 50000 6171` ->
   `seed=6171 n=50000 libpq=180006`; `parity 1952`, `both-refuse 42032`,
   `both-fail-at-runtime 1359`, `helper-stricter 3187`,
   `A:laundered/scheme-case 1143`, `A:laundered/invalid-percent-token 226`,
   `A:laundered/empty-query-segment 12`, `B:conn_mismatch_target_invalid 21`,
   `C:pw_mismatch/non-utf8-percent-byte 68`; `leak_pw_in_target 0`,
   `leak_password_key_on_argv 0`, `msg_leak 0`, `key_name_echo 0`,
   `helper-crash 0`. Every B is the F2 shape, every C the F1 byte class, every A
   one of the three F4 causes. #6221's `+` cause: 0 occurrences (fixed).
8. **Hygiene** (`lens8-gates.txt`): `python3.11 -m py_compile <both files>` ->
   `py_compile 3.11 OK` (3.11 is the oldest interpreter here; 3.9 is absent, so
   an AST scan stands in: `match` statements `[]`, `X | None` `[]`, imports
   stdlib-only `True` for both files); `grep shell=True` -> none; argparse and
   `subprocess.run([...])` lists only; `bash scripts/test/test-ci-workflow-invariants.sh`
   -> `ci.yml invariants: 38/38 PASS`; `bash scripts/check-required-contexts.sh`
   -> `check-required-contexts: OK (...)`;
   `bash scripts/check-count-assertion-declared.sh --range fa6b588e6..HEAD` ->
   `count-assertion-declared: clean (fa6b588e6..HEAD)`;
   `python3 scripts/check-docs-no-argv-secrets.py` ->
   `PASS: check-docs-no-argv-secrets: 2866 files scanned, 0 argv credentials`;
   `python3 scripts/test/test_workflow_pr_triggers_5447.py` -> `Ran 226 tests` / `OK`;
   `git diff fa6b588e6..HEAD --stat -- '*.rs' 'Cargo.*'` -> 0 lines;
   `cargo fmt --all --check` -> exit 0. Script mode `100755`, test `100644`.
9. **Docs/changelog drift**: the helper is mentioned only in
   `docs/DEV-CI-ENVIRONMENT.md` and `changelog.d/6161.fixed.md`. "empty host part"
   appears in the message (`:143`), docstring (`:38`), docs (`:221`), changelog
   (`:13`): R5-F4 MET. "percent-decoded only" and "as written": docstring `:40-41`,
   docs `:224-225`, changelog `:15`; "known libpq keyword": docstring `:45-46`,
   docs `:231`, changelog `:15`. Drift found: the socket-directory acceptance
   claim (F2), "passed on exactly as written" (F4 cause 3 drops empty segments),
   "allowlist of non-secret libpq parameters" (F5 omits nine non-secret keys),
   "every failure is one stderr line" (F6). One-line fixes: qualify each sentence
   or make the code match, per the finding.

## Issue requirements

| Source | Requirement (literal) | Status | Evidence |
|---|---|---|---|
| #6161 | "if `pg_available_extensions` lacks `age` on the macos-fed tier, restore" | MET | `:16-18` health = view lists age AND five pinned files; `ci.yml:1091` gates on `CI_NODE = macos-fed` |
| #6161 | "restore the four control/SQL files and `age.dylib` from a node-local AGE install directory outside Homebrew's trees (e.g. `/Users/fate/pg-age-stack/age-1.8.0/`)" | MET | `MANIFEST` `:99-105` (five files), `DEFAULT_AGE_DIR = ~/pg-age-stack/age-1.8.0` `:69` |
| #6161 | "then retry once" | MET | `run()` `:390` re-checks health once after install; the step then runs `CREATE EXTENSION` |
| #6161 | "fail with the current error only if the restore does not help" | MET | helper exit 1 + `::error::` at `ci.yml:1093`; the original `CREATE EXTENSION` error path at `:1098` is unchanged |
| #6161 | "Python helper per the Python-not-shell rule, called from the step" | MET | `scripts/ci/ensure-age-extension.py`, stdlib, argparse, list argv; `ci.yml:1092` |
| #6161 | "a runner-side copy of the AGE files into the brew-independent directory" | NODE-SIDE | not observable from the sandbox; documented at `docs/DEV-CI-ENVIRONMENT.md:189-192` |
| #6221 | "Replace `parse_qsl` with a split on `&` and `=` ... decoding key and value with `urllib.parse.unquote`" | MET | `:161`, `:174-175`, `:179` |
| #6221 | "keep the original raw segments minus the `password` one" | MET | `:182`, `:194`; lens 2 `options` cases parity |
| #6221 | tests: `+` reaches `PGPASSWORD` unchanged; kept `options=-c%20x%3Dy` reaches argv decodable | MET | `test_plus_in_query_password_reaches_pgpassword_unchanged`, `test_kept_query_segments_are_not_re_encoded` |
| round 6 | R5-F1 name only known libpq keywords | MET | lens 4 |
| round 6 | R5-F2 percent-only, `+` literal, raw segments | MET (byte class gap F1) | lens 2, lens 7 |
| round 6 | R5-F3 extra `=` in a later segment | MET | mutant M2 caught |
| round 6 | R5-F4 "an empty host part is refused" wording x4 | MET | evidence 9 |

## libpq parity table

Oracle = libpq 18.6 `PQconninfoParse`; helper = `psql_target()` at 15c72a590.
"target" is what reaches psql's argv; `PGPASSWORD` is the env value.

| Shape | libpq (original URL) | helper | Class |
|---|---|---|---|
| `u:Tr0ub%2B3@` / `u:Tr0ub+3@` / `?password=` same | password `Tr0ub+3` | `PGPASSWORD=Tr0ub+3` | parity |
| `%20`, `%25`, `%3D`, `%26` in password (both forms) | space, `%`, `=`, `&` | same | parity |
| `%zz`, lone `%`, `%2` in password (both forms) | error `invalid percent-encoded token` | accepts; `PGPASSWORD=Tr0ub%zz3` etc. | F4 |
| raw space in password | error `unexpected spaces found` | accepts; `PGPASSWORD='Tr0ub 3'` | F4 |
| `%00` in password (both forms) | error `forbidden value %00` | refused (NUL) | both refuse |
| `%ff`, `%e9` in password (both forms) | raw byte `\xff` / `\xe9` | `\xef\xbf\xbd` (U+FFFD) | **F1 pw-mismatch** |
| `%c3%a9` in password | `\xc3\xa9` | `\xc3\xa9` | parity |
| `options=-c%20a%3Db%2B1&password=x` | options `-c a=b+1` | segment kept raw; libpq reads `-c a=b+1` | parity |
| `options=-c+a&password=x` | `-c+a` | `-c+a` | parity |
| `options=%zz` / `options=a%00` kept | error | passed through; libpq errors at run time | both fail |
| password twice (userinfo + query) | query wins (`second`) | `second` | parity |
| password twice (query) | last wins | last | parity |
| `PASSWORD=` | error `invalid URI query parameter: "PASSWORD"` | refused, names `password` | both refuse |
| `?&&password=x`, `?&password=x` | error `missing key/value separator "=" ... ""` | accepts, emits no query | F4 |
| `?password=x&` (trailing) | ok | ok, no query | parity |
| `?sslmode=require&` (passthrough) | ok | kept verbatim | parity |
| `?application_name=a&&sslmode=require` (passthrough) | error | passed through; libpq errors | both fail |
| `#fragment` | reads past `#` (`sslmode=require#x`) | refused | helper stricter |
| `[::1]:5432` | host `::1` port `5432` | same | parity |
| `[::1` (unbalanced) | error | refused (`ValueError`) | both refuse |
| `h1/db?host=h2` | host `h2` | same (both kept) | parity |
| `postgresql://` | ok | ok | parity |
| `Postgres://`, `POSTGRESQL://` | error (`missing "="`: not a URI) | lower-cased and accepted | F4 |
| `u:pw@%2Fvar%2Frun/db` | host `/var/run` | same | parity |
| `u@/db?host=%2Ftmp`, `u:pw@/db?host=%2Ftmp` | host `/tmp` | same | parity |
| `:pw@/db?host=%2Ftmp` | host `/tmp`, password `pw` | target `postgres:/db?host=%2Ftmp` -> libpq error | **F2 conn-mismatch** |
| `postgres:///db?host=%2Ftmp` | host `/tmp` | refused (empty host part) | helper stricter |
| `u:@h/db` / `?password=` (empty) | password unset / empty | `PGPASSWORD=''` | parity (libpq then consults passfile either way) |
| `?ssl=true` | `sslmode=require` (JDBC alias) | refused as unlisted | helper stricter (F5) |
| `?pass%77ord=x` | password `x` | password `x`, moved to env | parity |
| `h1:1,h2:2` multi-host | host `h1,h2` port `1,2` | same | parity |
| `a%40b:pw@`, `a%3Ab:pw@`, `u:p%3Aq@` | user `a@b` / `a:b`, password `p:q` | same | parity |
| `h:abc` port | port `abc` (fails at connect) | same | parity |
| `?sslnegotiation=direct` etc. (15 keys) | accepted | refused "unlisted" | helper stricter (F5) |

---

```
REPORT lane=rev-6171-r6 branch=cloud/f1/rev-6171-r6 base=fa6b588e6b5dfa97370b4f073e60e66cb1ed1fa7 head=<this commit; the review file's own SHA cannot name itself> pushed=yes
COMMITS
<this commit> review(#6161): cloud adversarial review of PR #6171 head 15c72a590
ITEMS
#6161 | reviewed round 6 | REJECT | 8
GATES
runuser -u rev6171 -- python3 -m unittest scripts/test/test_ensure_age_extension_6161.py (tip 15c72a590, py3.13) -> Ran 52 tests in 5.846s / OK
runuser -u rev6171 -- python3.11 -m unittest scripts/test/test_ensure_age_extension_6161.py (tip) -> OK
runuser -u rev6171 -- python3 -m unittest scripts/test/test_ensure_age_extension_6161.py (4848491c2 script, tip tests) -> Ran 52 tests in 5.480s / FAILED (failures=10)
python3 -m unittest scripts/test/test_ensure_age_extension_6161.py (as root, tip) -> FAILED (failures=2) [F7: test_unwritable_lib_dir_fails_without_partial_state, test_share_failure_keeps_pinned_lib_file]
python3.11 -m py_compile scripts/ci/ensure-age-extension.py scripts/test/test_ensure_age_extension_6161.py -> py_compile 3.11 OK
bash scripts/test/test-ci-workflow-invariants.sh -> ci.yml invariants: 38/38 PASS
bash scripts/check-required-contexts.sh -> check-required-contexts: OK (release/v1.0.0: ...)
bash scripts/check-count-assertion-declared.sh --range fa6b588e6..HEAD -> count-assertion-declared: clean (fa6b588e6..HEAD)
python3 scripts/check-docs-no-argv-secrets.py -> PASS: check-docs-no-argv-secrets: 2866 files scanned, 0 argv credentials
python3 scripts/test/test_workflow_pr_triggers_5447.py -> Ran 226 tests in 0.544s / OK
cargo fmt --all --check -> exit 0 (first run exit 1 because the rustfmt component was absent from toolchain 1.98.0; installed with rustup component add rustfmt, then clean)
git diff fa6b588e6..HEAD --stat -- '*.rs' 'Cargo.*' -> 0 lines (no Rust in the PR; clippy and cargo test not run for a diff with zero Rust/Cargo changes)
python3 lens7_fuzz.py <script> 50000 6171 -> leak_pw_in_target 0, msg_leak 0, key_name_echo 0, C:pw_mismatch 68, B:conn_mismatch 21, A:laundered 1381
python3 lens3_leak.py <script> -> TOTAL LEAKS: 0 of 24 scenarios
python3 lens6_mutants.py userwt -> 10/10 CAUGHT; M11 (vacuity probe) SURVIVED
DECISIONS
Pushed only cloud/f1/rev-6171-r6 as the lane brief requires; the harness-designated branch claude/cloud-lane-rev-6171-r6-k0is9d was not pushed (brief: never push any other branch).
Oracle = ctypes PQconninfoParse on the psycopg-binary 3.3.6 bundled libpq (PQlibVersion 180006); psycopg.conninfo.conninfo_to_dict rejected the F1 byte class with UnicodeDecodeError, so it could not serve as the byte-exact oracle.
Tests were run as a created non-root user (rev6171) because the sandbox is uid 0 and the two chmod-based tests cannot fail as root (F7); root results are reported alongside.
Python 3.9 is not installed; 3.11 is the oldest present. py_compile under 3.11 plus an AST scan (no match, no X | None, stdlib-only) stands in for the 3.9 check.
Verdict REJECT rather than APPROVE: F1 contradicts the round's stated decoding rule and F2 contradicts a documented acceptance, both uncaught by the suite (F3 is vacuous). Security posture (no credential on argv/stdout/stderr) is intact; f1 may downgrade with that in view.
Review scratch (oracle, lens scripts, outputs) left under .local-runs/rev-6171-r6/ (gitignored) for re-run; the created worktree at .local-runs/rev-6171-r6/wt-4848491c was removed.
FOUND-NOT-FIXED
scripts/ci/ensure-age-extension.py:158,179 F1 unquote() replaces non-UTF-8 percent bytes with U+FFFD; libpq keeps the raw byte (password changes) — use errors="surrogateescape"
scripts/ci/ensure-age-extension.py:160,195 F2 ':pw@' userinfo with empty host becomes 'postgres:/db' via urlunsplit (postgres not in uses_netloc); libpq rejects the rewritten URL
scripts/test/test_ensure_age_extension_6161.py:426-438 F3 socket-directory acceptance test cannot fail on a refusal (mutant M11 survives)
scripts/ci/ensure-age-extension.py:137,158,171,179,194,195 F4 rewrite launders libpq-invalid URLs (scheme case; %zz/%/%2/raw space in password; leading or inner empty query segment when password removed)
scripts/ci/ensure-age-extension.py:79-92 F5 15 libpq 18.6 keywords and the ssl=true alias refused with the "unlisted" wording; docs/DEV-CI-ENVIRONMENT.md:227-229 calls the allowlist "non-secret libpq parameters"
scripts/ci/ensure-age-extension.py:395-401 F6 KeyboardInterrupt prints a traceback (no secret), contradicting changelog.d/6161.fixed.md:15-16 "every failure is one stderr line"
scripts/test/test_ensure_age_extension_6161.py:604-629 F7 two chmod-based tests fail under uid 0 on a correct script
scripts/ci/ensure-age-extension.py:41,79-85 F8 path/name keys (sslkey, sslcert, sslrootcert, sslcrl, passfile, service, krbsrvname, requirepeer) pass on argv by design; undocumented
docs/DEV-CI-ENVIRONMENT.md:222-225 drift: socket form "works" (F2) and "kept segments reach psql as written" (F4 cause 3)
```
