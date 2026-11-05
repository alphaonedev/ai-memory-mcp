# Documentation private-home-path gate

`<home>` denotes a redacted account home directory. Keep the real relative tail
after this placeholder. A dated record is repaired by replacing only the private
prefix; its other bytes, including Markdown hard breaks, remain unchanged.
Historical-truth preservation protects what was built and installed, not an
operator account name: the private-path policy takes precedence. The reviewed
install listing also replaces its owner and group columns with `<user>`; this
explicit column repair is separate from the scanner's home-prefix `--fix` mode.

The gate scans Markdown below `docs/` and rejects these lexical classes:

- Local paths with a `home` or `Users` component followed by an account name,
  with or without a following path. Nested and relative roots are included;
  `.` and `..` components are normalized before the home component is selected.
  Colon-adjacent paths (PATH lists, scp and container mounts) and `file://` paths
  are included. Recognized scheme URLs other than `file://`, and bare domain
  URL tokens, are excluded. A sentence-final period is kept;
  dots between account-name segments remain part of the account name.
- Named-home paths shaped as `~<account>/`, wherever they appear.
- Bare named homes shaped as `~<account>` in ordinary prose, inline code, or a
  fenced block whose language is empty, `sh`, `bash`, `zsh`, `shell`, or `console`
  (case-insensitive).

Markdown account escapes (`\_`, `\-`, `\.`) and U+200B, U+200C, U+200D and U+FEFF
are stripped for matching. Replacement spans map back to the original text so
the entire escaped or invisible account name is removed, leaving no name tail.

Numeric approximations remain unchanged. The sixteen established prose estimates
listed in `PROSE_APPROXIMATIONS` are exempt only as whole tokens in ordinary
prose. That set does not exempt inline code, shell-class fences, or named-home
paths, and is separate from the generic-account allowlist. Nameless `~/` and `$HOME`
do not reveal an account. Generic account names are explicit data in
`scripts/ci/docs_private_path_allow.json`; they are not inferred from prose.
The image account `aimem` and the illustrative accounts `u`, `op`, `operator`, `a`, and `ab`
are included so executable examples and historical illustrative text survive.

Three diagram estimates have narrowly scoped entries in
`scripts/ci/docs_private_path_exceptions.json`. Each entry records the path,
line number, exact line text without its newline terminator, SHA-256 of that
text, and a reason. Only an exact match can exempt a bare-name finding. An
altered line is not exempt, and an unused entry makes the gate fail. These
entries do not allow the same names in another line, file, or named-home path.

Run the check from the repository root:

```console
python3 scripts/ci/check_docs_private_paths.py
python3 scripts/ci/check_docs_private_paths.py --fix
```

The optional `--root`, `--allow-file`, and `--exceptions-file` arguments select
the documentation tree and policy files. Findings report file, line, and the
class `private-home-prefix`, never the matched private text. The summary includes
`exceptions_used` and `exceptions_unused`.
Exit codes are 0 for a clean scan or successful repair, 1 for remaining findings
or unused exceptions, and 2 for invalid policy or an input error. Repair refuses
to write when an exception is unused. Symlinked documentation is refused.

CI runs this gate immediately after docs-vs-SSOT in
`.github/workflows/c8-precheck.yml`. It is separate from the secrets scanner.
Mount paths and other leak classes are tracked separately under issue #8493.
Windows home paths, `/root`, and case-varied spellings of the absolute home
prefixes are not recognized by this lexical gate. Bare named-home tokens inside
fences for other languages are also excluded; absolute homes and named-home
paths remain checked there.
Percent-encoded paths, HTML entities and homoglyph characters are not decoded.
Format characters other than the four listed above are not normalized. Bare
account names outside home prefixes are not inferred by the scanner; reviewed
owner/group column repairs such as the install listing are made explicitly.
