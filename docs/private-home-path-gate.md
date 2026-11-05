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
  Every other scheme, including SSH, SFTP, rsync, git+ssh, SCP, SMB and NFS,
  scans as a local path. Detection sees the unmasked authority too: an authority
  equal to `home` or `Users`, with or without user information, cannot hide the
  next account component. This includes mixed-case file schemes.
  A compound scheme such as git+https is not HTTP(S).
  The scheme, user, host and port survive repair; the private prefix begins at
  the first path slash after the authority, including an empty authority.
  Authority boundaries use that slash, not the web-token alphabet: IPv6 brackets,
  ports and invisible host bytes survive unchanged. A scheme nested inside a
  non-web path is also checked; repair preserves the nested authority and its
  following path separator, including when the nested scheme is HTTP(S).
  This includes HTTP(S) headers glued after a slash in a relative, absolute or
  nameless-tilde local path. Standalone HTTP(S) headers at line start, after
  whitespace, opening parentheses/brackets, quotes or commas, and Markdown link
  targets remain public; nested headers inside a public web URL stay public.
  Before testing the nesting delimiter, the gate skips `INVISIBLE` characters
  leftward, so they cannot turn a local-path header into a public URL. The same
  nesting rule covers a tilde immediately before a web header: the bare-name
  matcher yields at `://`, preserving the tilde, header and authority during repair.
  Bare-domain spellings are checked as local paths. File-scheme markers and
  compiler options survive repair. `PATH_SWITCHES` preserves the established
  `-I` and `-L` prefixes; generic glued `-letters` switches also split before
  relative roots or named tilde homes, including `-isystemhome/`, `-iquoteUsers/`,
  `-Fvar/home/` and `-idirafter~<account>`. The same switch-length rule defines
  the tilde boundary; it has no separate option list. Otherwise a leading dash
  token splits at its first slash or tilde, preserving long options, digits, inner
  hyphens and trailing dashes, as in `--sysroot/`, `-m64/`, `-x-y/`, `-I-/` and
  `--include~<account>`. A `PATH_SWITCHES` spelling is recognized wherever it
  occurs, including word-glued `x-I~<account>`, `foo-L~<account>` and `--I~<account>`;
  the bytes before the named home remain unchanged. Option recognition ends at
  the first path delimiter; an option spelling inside an account is not a switch.
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
After repair, `--fix` rescans the replacement text and prints any remaining
findings without private text. A nonzero rescan returns `EXIT_FINDINGS` (1);
the summary reports `remaining`, and a successful repair requires it to be zero.

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
The first-slash rule keeps the whole option in `-Info/home/<account>` and
`-Lname.ext/home/<account>`; it does not delete the suffix of the dash token.
Fullwidth slash and homoglyphs are not normalized. `[` and `(` inside a web
path remain URL-legal. Relative paths such as `templates/home/<page>` are
checked by the same home-component rule and can therefore be refused.

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
Round 8 adds home-root authorities (F1), IPv6 and invisible authority bytes (F2),
nested scheme authorities (F3), dash-token spellings at a path slash (F4), and
generic switches adjacent to named tilde homes (F5). Earlier file-authority
productions remain in the grammar; an added slash must not remove their coverage.
Round 9 adds local paths crossed with glued HTTP(S) headers and home roots (F1),
plus complex dash tokens and word-glued option spellings crossed with tilde homes
(F2). Public web-header boundary controls remain part of the independent grammar.
Round 10 adds invisible characters between local slashes and web headers (F1),
and tilde-prefixed web headers crossed with home roots (F2). An independent
repair-rescan test also rejects a repairer that leaves a private prefix behind.
