#!/bin/bash
# One-line starter for runner_disk_hook.py (#8216). The GitHub Actions runner accepts only a .sh, .ps1 or .js
# hook path and passes no arguments, so this file does nothing but start the Python hook: one exec line, the
# interpreter by absolute path with -I, the script found next to this file without a PATH lookup. The event
# comes from the name this file is started under (runner_disk_hook_job-started.sh or
# runner_disk_hook_job-completed.sh, two symlinks to this file); see docs/ci/runner-disk-hook.md.
exec /opt/homebrew/bin/python3.12 -I "${0%/*}/runner_disk_hook.py" --invoked-as "${0##*/}"
