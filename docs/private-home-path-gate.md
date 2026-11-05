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
  both raw components and components normalized for `.` and `..` are checked,
  so a parent segment cannot hide an account already present in the text.
  Colon-adjacent paths (PATH lists, scp and container mounts) and file-scheme paths
  are included, with case-insensitive schemes and zero, one or multiple slashes.
  Only HTTP and HTTPS URLs (`WEB_URL_SCHEMES`) are excluded case-insensitively,
  including their internal punctuation, query and fragment. `URL_TOKEN_CHARS`
  contains RFC 3986 unreserved and reserved characters plus percent, except
  comma, closing bracket, closing parenthesis and apostrophe. Whitespace and
  every character outside that positive set end the token: C0 controls, DEL,
  U+200B, U+200C, U+200D, U+FEFF, angle brackets, double quote, backtick, vertical
  bar, backslash, caret and braces. URL boundaries precede account normalization.
  Every other scheme,
  including SSH, SFTP, rsync, git+ssh, SCP, SMB and NFS, scans as a local path.
  A compound scheme such as git+https is not HTTP(S).
  The scheme, user, host and port survive repair; the private prefix begins at
  the first path slash after the authority, including an empty authority.
  Bare-domain spellings are checked as local paths. File-scheme markers and
  compiler options survive repair. `PATH_SWITCHES` preserves the established
  `-I` and `-L` prefixes; generic glued `-letters` switches also split before
  relative roots, including `-isystemhome/`, `-iquoteUsers/`, and `-Fvar/home/`.
  A sentence-final period is kept; dots between
  account-name segments remain part of the account name.
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
Apostrophe terminates a URL token; an emphasis star following a URL remains
public because star is URL-legal. The `git+https` and `ftp` schemes scan as text.
The established `-Info/home/<account>` spelling keeps `-I` and repairs the
remaining path, consistently with the earlier compiler-prefix rule.

The independent shape grammar in
`scripts/ci/tests/docs_private_path_shapes_8493.py` combines roots, account classes,
left contexts, right contexts and inner path shapes. Its expected spans are built
from those pieces, without calling scanner helpers or using scanner patterns.
Each private case must be detected, repaired byte-exactly, and clean on rescan;
public cases must remain unchanged. Named-tilde homes retain their anywhere rule,
including URL paths; the web-host exemption applies to absolute home components.
Every future review finding adds a grammar axis before the implementation fix.
Round 6 adds URL-internal punctuation (L1), relative roots crossed with every
left context (Q1), and lower- and upper-case non-web schemes (Q2). HTTP and HTTPS
remain public. The declared percent-encoded slash and backslash limits stay
explicit grammar cases; changing those limits also requires changing that axis.
Round 7 adds URL-illegal terminators (F1), non-web authority forms (F2), and
generic glued switches crossed with relative roots (F3). The generator declares
its own literals independently of the gate's named constants.
