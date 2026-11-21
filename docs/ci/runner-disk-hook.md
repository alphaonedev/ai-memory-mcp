# Self-hosted runner disk hook

`scripts/ci/runner_disk_hook.py` is the GitHub Actions runner's job-started and job-completed hook for the
self-hosted macOS runners (#8216). Several runners share one boot disk, and each keeps a cargo `target`
directory in its work folder (27 to 51 GiB each, growing per job). A full boot disk ends every job and every
lane on the host. The hook clears this runner's cargo target directories when the disk is low, so nobody has to
clear them by hand.

## What it does

| Event | Floor | Action |
|---|---|---|
| `job-completed` | `CLEAR_BELOW_GIB_AFTER_JOB = 150` GiB | below the floor: remove the cargo target directories in this runner's work folder; always exits 0 |
| `job-started` | `START_FLOOR_GIB = 60` GiB | the same check with this floor, plus the work-folder ceiling below; when the free space is still under the floor after the clear, exit 75 (see "Exit code") |

The floor is compared in bytes: `floor_gib * 1024**3`. Free space exactly at the floor is enough (the comparison
is strictly below). The GiB figures in the log are truncated, never rounded up, so a value printed as `59.99`
cannot be shown as 60. Both constants are module-level names in the script and the tests use them.

## Work-folder ceiling

Every runner work folder has a ceiling, `WORK_FOLDER_CEILING_GIB = 40` (`WORK_FOLDER_CEILING_BYTES` is the same
value in bytes). The ceiling is on the allocated bytes of the work root (`st_blocks * 512` of each inode, a
hard-linked inode counted once), so a sparse file counts what it occupies and a hard link is not counted twice.
At `job-started` the hook measures the work root and, when it is strictly over the ceiling, removes the cargo
target directories (the same proven candidates as below and nothing else in the work folder), whatever the free
space is. At exactly the ceiling nothing is removed. The measurement walks with `O_NOFOLLOW` directory
descriptors: a symlink is counted as the link and never followed, and a directory on another device is not
entered. A folder that cannot be read, or has more than `MAX_WALK_ENTRIES` entries (files and directories both
count), is a refusal with its own decision (`refused-measure`, or `entry-cap` when there is enough free space) and
its own reason; it is never counted as under the ceiling. `job-completed` does not measure the folder. The log
line carries `folder_bytes_before` and `folder_bytes_after` (`unknown` when the folder was not measured).

**The ceiling does not bound growth inside one job.** It is checked at job start and job end only. Measured on
2026-11-21: a target that started at 0 reached 23 GiB in 33 minutes inside one job, and a warm target reached
51 GiB. The start floor is what bounds a job: it makes sure the job begins with room for that growth. A target is
almost all of `target/debug/deps`, which holds one linked test executable per test target.

There is no sudo fallback: a hook must never wait on a password prompt. A directory that still cannot be removed
is one reason in the log line.

## Layout it supports

`RUNNER_WORKSPACE` is `<runner root>/_work/<repo>` and `GITHUB_WORKSPACE` is `<RUNNER_WORKSPACE>/<repo>`. The work
root is `RUNNER_WORKSPACE`; a candidate is `<work root>/<repo>/target`. A directory named anything else
(`Target`, `target2`) or at another depth is kept. A runner never touches another runner's work folder.

## What it removes, and what it refuses

A directory is removed only when all of these hold. Every other case is a refusal with its own exact reason in
the log and on stderr, and nothing is removed.

1. The work root is set, non-empty, absolute, free of `..`, not `/`, not the home directory, has at least three
   path parts, is not under the system data volume (the `Data` folder of the `Volumes` folder below `/System`), is named `<runner root>/_work/<repo>` (its parent is a
   directory named `_work`), exists, is a real directory (not a symlink), is not a mount point and is on the
   same device as its parent (the work root is not a separate volume).
2. The candidate is named exactly `target`, is a real directory (not a symlink), resolves inside the work root and
   is on the work root's device.
3. It holds a regular `CACHEDIR.TAG` file whose first line is `Signature: 8a477f597d28d172789f06886806bc55`.
4. The removal is done by `scripts/ci/safe_remove.py`. It opens the directory once by file descriptor
   (`O_NOFOLLOW | O_DIRECTORY`, relative to the parent descriptor), proves the tag through that descriptor,
   removes the tree through the same descriptor on one device with bounded depth, and removes the tag last. A tree
   deeper than the cap is refused before anything is unlinked. There is no `chmod` subprocess: a directory that
   cannot be entered is a refusal with its reason. Each tag problem (missing, symlink, not a regular file,
   wrong signature, unreadable) has its own reason.

At job start, after a successful free-space read, the hook also removes `.local-runs/test-tmp` from the work root
and from each real (non-symlink) directory directly below it, through the same descriptor-based engine (every open
is relative to its parent descriptor with `O_NOFOLLOW`, on the work root's device, no tag required). A symlinked
`.local-runs` or `test-tmp` is a refusal and is never followed. There is no ACL strip and no `chmod` subprocess: a
tree the removal cannot enter or unlink is a refusal that names the operating system's reason. `job-completed`
never touches `test-tmp`, a failed free-space read removes nothing, and `--dry-run` only lists what would go. Each
outcome is one note in the line's `reason` (`test-tmp removed`, `test-tmp would be removed`, `test-tmp partial`,
`test-tmp not cleared`); `removed=` and `entries=` count `target` directories only.

A free-space read that fails, returns nothing or returns a negative value is a refusal to decide: nothing is
removed and the reason is logged. It is never read as 0 free or as plenty.

Every text that reaches stderr or the log (a runner name, a path, an OS error message) goes through one funnel
that escapes control characters, escape sequences and `%`-sequences and caps the length, so an attacker-chosen
repository or runner name cannot forge a log line or a terminal sequence.

## Exit code

The exit code is computed in one place from the state after the action:

| Case | Exit |
|---|---|
| `job-completed`, every outcome | 0 |
| `job-started`, free space at or above the floor after the clear | 0 |
| `job-started`, refused to decide, dry run, or `ENFORCE_START_FLOOR = False` | 0 |
| `job-started`, free space under the floor after the clear, `ENFORCE_START_FLOOR = True` | 75 (`EXIT_BELOW_FLOOR`) |

decision: exit non-zero at job-started below `START_FLOOR_GIB` over always exit 0, because a job that starts
without room dies of a full disk 40 to 60 minutes in and takes the host's other jobs with it, while a refused
start costs seconds (3-agent vote (71472661), tally A 3, B 0). `job-completed` never exits non-zero for the
floor: a failing end hook would turn a finished job red. The kill switch is the module constant
`ENFORCE_START_FLOOR`; both of its values are tested.

The below-floor refusal is one fixed, greppable line, on stderr (after the `runner-disk-hook: ` prefix) and in the
log:

```
<UTC> decision=below-floor event=job-started free_bytes=<n|unknown> floor_bytes=<n> runner=<name>
```

## Risk and rollout

**Risk.** A runner whose free space is under the floor fails every job routed to it within seconds, and GitHub
does not move the job to another runner. With the floor enforced, a runner on a full disk takes every job
that is sent to it down with it until space is back.

**Rollout rule.** Enable the hook on one runner first. A `decision=below-floor` line in the log means: stop that
runner's service until space is back, then start it again. Enable the next runner only after the first has run
jobs with no `below-floor` line.

## Log

Every call appends exactly one line to the log. The path is `--log` (absolute), else the absolute path in the
environment variable `RUNNER_DISK_HOOK_LOG`, else `<home>/ai-tmp/runner-disk-hook.log`. A relative log path is a
refusal. The file is created with mode `0600` and the default directory with `0700`; the file is opened with
`O_NOFOLLOW`:

```
<UTC time> runner=<name> event=<event> free_before_gib=<n|unknown> free_after_gib=<n|unknown> folder_bytes_before=<n|unknown> folder_bytes_after=<n|unknown> decision=<decision> removed=<count> entries=<count> paths=<JSON list> reason=<JSON string>[ dry-run]
```

`decision` is one of `enough-free`, `clear`, `would-remove`, `partial`, `no-target`, `refused-target`,
`refused-measure`, `entry-cap`, `below-floor`, `refused`. A free value with the prefix `input:` came from
`--free-gib` (a test input), not from the disk.

A log that cannot be written (a full disk is the usual cause) does not stop the removal: the failure and the line
go to stderr, because refusing to clear would keep the disk full.

## Wiring

The runner reads its hook paths from its `.env` file at start, and accepts only a path ending in `.sh`, `.ps1` or
`.js`, with no arguments. The hook therefore starts through `scripts/ci/runner_disk_hook.sh`, a file that holds one
`exec` line. The event comes from the name the file is started under, so the install directory holds three
symlinks (the install directory is outside the runner work folders; use the same directory for every runner):

```
<install dir>/runner_disk_hook.py                    -> <repo>/scripts/ci/runner_disk_hook.py
<install dir>/runner_disk_hook_job-started.sh        -> <repo>/scripts/ci/runner_disk_hook.sh
<install dir>/runner_disk_hook_job-completed.sh      -> <repo>/scripts/ci/runner_disk_hook.sh
```

The wrapper runs `/opt/homebrew/bin/python3.12 -I "${0%/*}/runner_disk_hook.py" --invoked-as "${0##*/}"`, so
the interpreter is an absolute path and the script is found next to the link without a PATH lookup. The hook
finds `safe_remove.py` next to the real file of `runner_disk_hook.py`. Any other invocation name is a named
refusal (exit 0, logged). In each runner's `.env`:

```
ACTIONS_RUNNER_HOOK_JOB_STARTED=<install dir>/runner_disk_hook_job-started.sh
ACTIONS_RUNNER_HOOK_JOB_COMPLETED=<install dir>/runner_disk_hook_job-completed.sh
```

decision: the event from the invocation name over a second env var for the event, because the runner passes no
arguments and no environment of its own to a hook path.

Calling the Python file directly (a dry run, a test) takes exactly one of `--event {job-started,job-completed}` or
`--invoked-as <name>`; neither, or both, is a refusal.

## Dry run

`--dry-run` takes the full decision, writes the log line (ending in ` dry-run`) and removes nothing. A dry run
always exits 0. Run it against a scratch work root:

```
RUNNER_NAME=<runner name> RUNNER_WORKSPACE=<scratch>/_work/<repo> \
  /opt/homebrew/bin/python3.12 -I scripts/ci/runner_disk_hook.py --event job-completed --dry-run --free-gib 10 --log <scratch log>
```

`--free-gib` is a test input: it replaces the disk reading and must be a finite number. Leave it out to use the real
free space.

## Tests

`scripts/ci/tests/test_runner_disk_hook_8216.py` and `scripts/ci/tests/test_safe_remove_8216.py` run in the
`python3 -m unittest discover -s scripts/ci/tests` step of `.github/workflows/ci.yml` (job `build-script-vetting`).
