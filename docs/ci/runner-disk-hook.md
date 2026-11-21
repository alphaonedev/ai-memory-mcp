# Self-hosted runner disk hook

`scripts/ci/runner_disk_hook.py` is the GitHub Actions runner's job-started and job-completed hook for the
self-hosted macOS runners (#8216). Several runners share one boot disk, and each keeps a cargo `target`
directory in its work folder (27 to 51 GiB each, growing per job). A full boot disk ends every job and every
lane on the host. The hook clears this runner's cargo target directories when the disk is low, so nobody has to
clear them by hand.

## What it does

| Event | Floor | Action |
|---|---|---|
| `--event job-completed` | `CLEAR_BELOW_GIB_AFTER_JOB = 150` GiB | below the floor: remove the cargo target directories in this runner's work folder |
| `--event job-started` | `START_FLOOR_GIB = 60` GiB | strip macOS ACLs and remove `.local-runs/test-tmp` (the old shell hook), then the same check with this floor |

Free space is exactly at the floor: nothing is removed (the comparison is strictly below). Both constants are
module-level names in the script and the tests use them.

There is no sudo fallback: a hook must never wait on a password prompt. A directory that still cannot be removed
is one reason in the log line. The old hook's unbounded `find` fallback for a `test-tmp` directory is not ported:
only `<base>/.local-runs/test-tmp` for the work root, the workspace and the workspace's parent is cleared.

## Layout it supports

`RUNNER_WORKSPACE` is `<runner root>/_work/<repo>` and `GITHUB_WORKSPACE` is `<RUNNER_WORKSPACE>/<repo>`. The work
root is `RUNNER_WORKSPACE`; a candidate is `<work root>/<repo>/target`. A directory named anything else
(`Target`, `target2`) or at another depth is kept. A runner never touches another runner's work folder.

## What it removes, and what it refuses

A directory is removed only when all of these hold. Every other case is a refusal with its own reason in the log
and on stderr, and nothing is removed.

1. The work root is set, non-empty, absolute, free of `..`, not `/`, not the home directory, has at least three
   path parts, exists, is a real directory (not a symlink) and is not a mount point.
2. The candidate is named exactly `target`, is a real directory (not a symlink), resolves inside the work root and
   is on the work root's device.
3. It holds a regular `CACHEDIR.TAG` file whose first line is `Signature: 8a477f597d28d172789f06886806bc55`.
4. The removal opens each directory with `O_NOFOLLOW` through a directory file descriptor, unlinks a symlink
   instead of entering it, and never crosses a device boundary.

A free-space read that fails, returns nothing or returns a negative value is a refusal to decide: nothing is
removed (the `test-tmp` directories included) and the reason is logged. It is never read as 0 free or as plenty.

## Exit code

The hook exits 0 on every path, refusals and errors included. decision: exit 0 over a failing exit, because a
failing runner hook turns every job on that runner red and hides the real result. The reason is in the log line
and on stderr; the conductor's disk waiter is the backstop.

## Log

Every call appends exactly one line to the log. The path is `--log`, else the absolute path in the environment
variable `RUNNER_DISK_HOOK_LOG`, else `<home>/ai-tmp/runner-disk-hook.log` (set the variable in the runner `.env`
to move it):

```
<UTC time> runner=<name> event=<event> free_before_gib=<n|unknown> free_after_gib=<n|unknown> decision=<clear|enough-free|refused> removed=<count> paths=<JSON list> reason=<JSON string>[ dry-run]
```

A log that cannot be written (a full disk is the usual cause) does not stop the removal: the failure and the line
go to stderr, because refusing to clear would keep the disk full.

## Wiring

The runner reads its hook paths from its `.env` file at start. In each runner's `.env`:

```
ACTIONS_RUNNER_HOOK_JOB_STARTED=<path to runner_disk_hook.py> --event job-started
ACTIONS_RUNNER_HOOK_JOB_COMPLETED=<path to runner_disk_hook.py> --event job-completed
```

Open point, not decided here: whether the runner accepts a hook path that does not end in `.sh` or `.ps1`, and
whether it accepts arguments on that value. The conductor tests this on an idle runner. Until that is known, do
not rely on either answer.

## Dry run

`--dry-run` takes the full decision, writes the log line (ending in ` dry-run`) and removes nothing. Run it from
the runner's work folder context:

```
RUNNER_NAME=<runner name> RUNNER_WORKSPACE=<runner root>/_work/<repo> \
  /opt/homebrew/bin/python3.12 scripts/ci/runner_disk_hook.py --event job-completed --dry-run --free-gib 10 --log <scratch log>
```

`--free-gib` is a test input: it replaces the disk reading. Leave it out to use the real free space.

## Tests

`scripts/ci/tests/test_runner_disk_hook_8216.py` runs in the `python3 -m unittest discover -s scripts/ci/tests`
step of `.github/workflows/ci.yml`.
